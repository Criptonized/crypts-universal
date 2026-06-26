-- engine/auth.lua -- Crypt.Auth: the client side of the account-based key system (distribution Phase 1).
-- ============================================================================
-- See HANDOFF_DISTRIBUTION.md. A 1-time KEY unlocks account CREATION; then users LOGIN with username/password.
-- This module is the CLIENT: pure validation/format logic + a session cache + an HTTP client to the (future)
-- Cloudflare Worker, with a built-in MOCK backend so the entire flow (activate -> register -> login -> session
-- -> recover) works OFFLINE until the Worker is deployed. Real auth/storage/hashing live server-side; the mock
-- here is a demo only (its "hash" is NOT secure). Pure helpers are isolation-tested. Off by default -- the gate
-- only shows when getgenv().Crypt_RequireAuth is set, so normal usage is never blocked.
-- ============================================================================
return function(Crypt)
	local HttpService = game:GetService("HttpService")
	local Auth = { base = nil, session = nil, _mock = nil }

	-- ===== pure helpers (mirrored in spy_reference/auth_run.lua) =====
	local ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	-- a deterministic check char over a string body (position-weighted mod 36). Pure -- isolation-tested.
	local function keyCheckChar(body)
		local sum = 0
		for i = 1, #body do sum = (sum + body:byte(i) * i) % 36 end
		return ALPHABET:sub(sum + 1, sum + 1)
	end
	-- a well-formed key: CRYPT-XXXXX-XXXXX-C, groups upper-alnum, C the checksum. Pure -- isolation-tested.
	local function makeKey(g1, g2) local body = "CRYPT-" .. g1 .. "-" .. g2; return body .. "-" .. keyCheckChar(body) end
	local function validKeyFormat(key)
		if type(key) ~= "string" then return false end
		local g1, g2, c = key:match("^CRYPT%-(%w%w%w%w%w)%-(%w%w%w%w%w)%-(%w)$")
		if not g1 then return false end
		if not (g1:match("^[0-9A-Z]+$") and g2:match("^[0-9A-Z]+$") and c:match("^[0-9A-Z]$")) then return false end
		return keyCheckChar("CRYPT-" .. g1 .. "-" .. g2) == c
	end
	-- username rules: 3-20 chars, must start with a letter, then letters/digits/underscore. Pure -- tested.
	local function validUsername(name)
		if type(name) ~= "string" then return false, "username required" end
		if #name < 3 or #name > 20 then return false, "3-20 characters" end
		if not name:match("^%a[%w_]*$") then return false, "start with a letter; letters/digits/_ only" end
		return true, "ok"
	end
	-- password rules: >= 8 chars; strength = length + variety. Pure -- tested.
	local function validPassword(pw)
		if type(pw) ~= "string" or #pw < 8 then return false, "weak", "at least 8 characters" end
		local classes = 0
		if pw:match("%l") then classes = classes + 1 end
		if pw:match("%u") then classes = classes + 1 end
		if pw:match("%d") then classes = classes + 1 end
		if pw:match("[^%w]") then classes = classes + 1 end
		local strength = (#pw >= 12 and classes >= 3) and "strong" or (classes >= 2 and "ok" or "weak")
		return true, strength, "ok"
	end
	-- a basic email shape check (mirrors the Worker's validEmail); real validation is the emailed code. Pure -- tested.
	local function validEmail(e)
		if type(e) ~= "string" or #e > 254 then return false end
		return e:match("^[^@%s]+@[^@%s]+%.[^@%s]+$") ~= nil
	end
	-- launch decision: a cached, non-expired session -> run the app; else show the gate. Pure -- tested.
	local function launchDecision(session, now)
		if type(session) ~= "table" or not session.token or session.token == "" then return "gate" end
		if session.exp and tonumber(session.exp) and now and now >= tonumber(session.exp) then return "gate" end
		return "app"
	end
	-- auth.txt round-trip: token=...;user=...;exp=...  (pure, no secrets beyond the opaque token). Pure -- tested.
	local function serialize(s)
		s = s or {}
		return ("token=%s;user=%s;exp=%s"):format(tostring(s.token or ""), tostring(s.username or ""), tostring(s.exp or 0))
	end
	local function parse(text)
		local out = {}
		for kv in tostring(text or ""):gmatch("[^;]+") do local k, v = kv:match("^(%w+)=(.*)$"); if k then out[k] = v end end
		return { token = (out.token ~= "" and out.token) or nil, username = out.user, exp = tonumber(out.exp) }
	end
	Auth.keyCheckChar, Auth.makeKey, Auth.validKeyFormat = keyCheckChar, makeKey, validKeyFormat
	Auth.validUsername, Auth.validPassword, Auth.launchDecision = validUsername, validPassword, launchDecision
	Auth.serialize, Auth.parse = serialize, parse
	Auth.validEmail = validEmail
	Crypt._authKeyCheck, Crypt._authValidKey, Crypt._authValidUser, Crypt._authValidPass = keyCheckChar, validKeyFormat, validUsername, validPassword
	Crypt._authLaunch, Crypt._authSerialize, Crypt._authParse, Crypt._authMakeKey = launchDecision, serialize, parse, makeKey
	Crypt._authValidEmail = validEmail

	-- ===== MOCK backend (offline demo; replaced by the real Worker via getgenv().Crypt_AuthBase) =====
	local function mockHash(s) local n = 5381; for i = 1, #s do n = (n * 33 + s:byte(i)) % 2147483647 end; return tostring(n) end
	local function token() local t = ""; for _ = 1, 24 do local r = math.random(1, 36); t = t .. ALPHABET:sub(r, r) end; return t end
	local M = {
		keys = {}, accounts = {}, activations = {}, sessions = {},
		demoKeys = {},
	}
	-- seed a few valid demo keys so the flow is testable offline
	for _, gg in ipairs({ { "DEMO1", "AAAAA" }, { "DEMO2", "BBBBB" }, { "TRIAL", "CRYPT" } }) do
		local k = makeKey(gg[1], gg[2]); M.keys[k] = { status = "unused" }; M.demoKeys[#M.demoKeys + 1] = k
	end
	function M.handle(endpoint, body)
		body = body or {}
		if endpoint == "/activate" then
			local k = body.key
			if not validKeyFormat(k) then return false, { error = "bad key format" } end
			local rec = M.keys[k]
			if not rec or rec.status ~= "unused" then return false, { error = "key invalid or already used" } end
			local at = token(); M.activations[at] = k; rec.status = "pending"
			return true, { activationToken = at }
		elseif endpoint == "/register" then
			local key = M.activations[body.activationToken]
			if not key then return false, { error = "activation expired -- re-enter your key" } end
			local uok = validUsername(body.username); local pok = validPassword(body.password)
			if not uok then return false, { error = "invalid username" } end
			if not pok then return false, { error = "weak password" } end
			if M.accounts[(body.username or ""):lower()] then return false, { error = "username taken" } end
			local rc = makeKey("RECOV", string.upper((body.username or "xxxxx"):sub(1, 5) .. "00000"):sub(1, 5))
			M.accounts[body.username:lower()] = { username = body.username, hash = mockHash(body.password), email = body.email, recovery = rc, hwid = body.hwid, resets = 3, banned = false }
			M.keys[key].status = "used"; M.activations[body.activationToken] = nil
			local tk = token(); M.sessions[tk] = body.username:lower()
			return true, { session = tk, username = body.username, exp = os.time() + 7 * 86400, recoveryCode = rc, tier = "basic" }
		elseif endpoint == "/login" then
			local acc = M.accounts[(body.username or ""):lower()]
			if not acc or acc.hash ~= mockHash(body.password or "") then return false, { error = "wrong username or password" } end
			if acc.banned then return false, { error = "account banned" } end
			local tk = token(); M.sessions[tk] = acc.username:lower()
			return true, { session = tk, username = acc.username, exp = os.time() + 7 * 86400, tier = "basic" }
		elseif endpoint == "/session" then
			local u = M.sessions[body.session]
			if not u then return false, { error = "session invalid" } end
			return true, { ok = true, username = u, tier = "basic", exp = os.time() + 7 * 86400 }
		elseif endpoint == "/forgot" then
			local q = (body.usernameOrEmail or ""):lower()
			for _, acc in pairs(M.accounts) do
				if acc.username:lower() == q or (acc.email and acc.email:lower() == q) then
					acc.resetCode = tostring(math.random(100000, 999999))
					return true, { ok = true, devCode = acc.resetCode }   -- real backend EMAILS this; offline surfaces it
				end
			end
			return true, { ok = true }   -- uniform; never reveal whether the user/email exists
		elseif endpoint == "/reset" then
			for _, acc in pairs(M.accounts) do
				if acc.recovery == body.resetCode or (acc.resetCode and acc.resetCode == body.resetCode) then
					acc.hash = mockHash(body.newPassword or ""); acc.resetCode = nil; return true, { ok = true }
				end
			end
			return false, { error = "invalid or expired code" }
		elseif endpoint == "/recover-username" then
			local email = (body.email or ""):lower(); local names = {}
			for _, acc in pairs(M.accounts) do if acc.email and acc.email:lower() == email then names[#names + 1] = acc.username end end
			return true, { ok = true, devUsernames = (#names > 0 and names or nil) }   -- real backend EMAILS these
		elseif endpoint == "/link-email" then
			local u = M.sessions[body.session]; if not u then return false, { error = "session invalid -- sign in again" } end
			if not validEmail(body.email) then return false, { error = "enter a valid email" } end
			local acc = M.accounts[u]; acc.pendingEmail = body.email; acc.emailCode = tostring(math.random(100000, 999999))
			return true, { ok = true, devCode = acc.emailCode }   -- real backend EMAILS this
		elseif endpoint == "/verify-email" then
			local u = M.sessions[body.session]; if not u then return false, { error = "session invalid -- sign in again" } end
			local acc = M.accounts[u]
			if not (acc.pendingEmail and acc.emailCode) then return false, { error = "nothing to verify -- request a code first" } end
			if tostring(body.code) ~= acc.emailCode then return false, { error = "wrong code" } end
			acc.email = acc.pendingEmail; acc.emailVerified = true; acc.pendingEmail = nil; acc.emailCode = nil
			return true, { ok = true, email = acc.email }
		end
		return false, { error = "unknown endpoint" }
	end
	Auth._mock = M

	-- ===== HTTP client (real Worker if Crypt_AuthBase set, else the mock) =====
	local function httpFn() return (syn and syn.request) or http_request or request or (http and http.request) end
	function Auth.request(endpoint, body)
		local base = Auth.base or (getgenv and getgenv().Crypt_AuthBase)
		local fn = httpFn()
		if base and fn then
			local ok, res = pcall(function()
				return fn({ Url = base .. endpoint, Method = "POST", Headers = { ["Content-Type"] = "application/json" }, Body = HttpService:JSONEncode(body or {}) })
			end)
			if ok and res and res.Body then
				local dok, data = pcall(function() return HttpService:JSONDecode(res.Body) end)
				if dok then return ((res.StatusCode or 200) < 300 and data.error == nil), data end
			end
			return false, { error = "network error" }
		end
		return M.handle(endpoint, body)
	end

	-- ===== session cache (workspace/Crypt/auth.txt) =====
	local PATH = "Crypt/auth.txt"
	function Auth.saveSession(s)
		Auth.session = s
		pcall(function()
			if type(makefolder) == "function" and type(isfolder) == "function" and not isfolder("Crypt") then makefolder("Crypt") end
			if type(writefile) == "function" then writefile(PATH, serialize(s)) end
		end)
	end
	function Auth.loadSession()
		local s = nil
		pcall(function() if type(isfile) == "function" and isfile(PATH) and type(readfile) == "function" then s = parse(readfile(PATH)) end end)
		Auth.session = s
		return launchDecision(s, os.time()) == "app" and s or nil
	end
	function Auth.clearSession() Auth.session = nil; pcall(function() if type(delfile) == "function" then delfile(PATH) elseif type(writefile) == "function" then writefile(PATH, "") end end) end

	-- ===== flow (in-game; returns ok, data/errmsg) =====
	local function hwid() local ok, id = pcall(function() return (gethwid and gethwid()) or (syn and syn.crypt and "syn") or "unknown" end); return ok and tostring(id) or "unknown" end
	function Auth.activate(key) local ok, d = Auth.request("/activate", { key = key, hwid = hwid() }); return ok, ok and d.activationToken or (d and d.error) end
	function Auth.register(activationToken, username, password, email)
		local ok, d = Auth.request("/register", { activationToken = activationToken, username = username, password = password, email = email, hwid = hwid() })
		if ok then Auth.saveSession({ token = d.session, username = d.username, exp = d.exp }) end
		return ok, d
	end
	function Auth.login(username, password)
		local ok, d = Auth.request("/login", { username = username, password = password, hwid = hwid() })
		if ok then Auth.saveSession({ token = d.session, username = d.username, exp = d.exp }) end
		return ok, d
	end
	function Auth.validateSession()
		if not (Auth.session and Auth.session.token) then return false end
		local ok = Auth.request("/session", { session = Auth.session.token, hwid = hwid() })
		return ok
	end
	function Auth.forgot(userOrEmail) return Auth.request("/forgot", { usernameOrEmail = userOrEmail }) end
	function Auth.reset(code, newPassword) return Auth.request("/reset", { resetCode = code, newPassword = newPassword }) end
	function Auth.recoverUsername(email) return Auth.request("/recover-username", { email = email }) end
	function Auth.linkEmail(email)
		if not (Auth.session and Auth.session.token) then return false, { error = "sign in first" } end
		return Auth.request("/link-email", { session = Auth.session.token, email = email })
	end
	function Auth.verifyEmail(code)
		if not (Auth.session and Auth.session.token) then return false, { error = "sign in first" } end
		return Auth.request("/verify-email", { session = Auth.session.token, code = code })
	end

	Crypt.Auth = Auth
end
