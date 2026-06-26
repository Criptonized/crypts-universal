-- Crypt's Universal Script -- gated one-line loader (server-enforced sign-in).
-- ============================================================================
-- The ONLY line an end user runs:
--   loadstring(game:HttpGet("https://raw.githubusercontent.com/Criptonized/crypts-universal/main/loader.lua"))()
--
-- HOW THE GATE IS ENFORCED (not bypassable by deleting a getgenv flag): this loader is public, but it
-- contains ONLY the sign-in client (engine/auth.lua + ui/auth_gate.lua) -- never the real features. It
-- authenticates against the live Cloudflare Worker; the Worker's /script endpoint returns the real
-- (private) script from R2 storage ONLY for a valid session. The real script is not served raw. Revoke
-- a user by banning the account / bumping its token version -> their next /script call 403s instantly.
--
-- DEV bypass (the project owner, during development): fetch main.lua directly with a base set, e.g.
--   getgenv().Crypt_Base = "https://raw.githubusercontent.com/Criptonized/crypts-universal/main/"
--   loadstring(game:HttpGet(getgenv().Crypt_Base .. "main.lua"))()
-- (That path stays open only while the source modules remain in a readable repo -- see HANDOFF_DISTRIBUTION.md.)
-- ============================================================================
local AUTH_BASE = "https://crypt-auth.themanwithslavbrains.workers.dev"             -- the live auth + delivery Worker
local PUB = "https://raw.githubusercontent.com/Criptonized/crypts-universal/main/"  -- public sign-in modules ONLY

getgenv().Crypt_AuthBase = AUTH_BASE  -- so Crypt.Auth talks to the real Worker (not its built-in offline mock)

local HttpService = game:GetService("HttpService")

-- a minimal Crypt scaffold: just enough to host the auth client + the sign-in card (no engine, no features)
local Crypt = { Name = "Crypt's Universal" }

local function httpGet(url)
	local ok, body = pcall(function() return game:HttpGet(url) end)
	return ok and body or nil
end
-- fetch + run a public module (module contract: the file returns function(Crypt))
local function loadModule(path)
	local src = httpGet(PUB .. path)
	if not src then error("[Crypt] could not fetch " .. path .. " -- check your internet / executor HTTP", 0) end
	local fn, err = loadstring(src, "=" .. path)
	if not fn then error("[Crypt] failed to compile " .. path .. ": " .. tostring(err), 0) end
	fn()(Crypt)
end
loadModule("engine/auth.lua")
loadModule("ui/auth_gate.lua")

-- the executor's HTTP-request function (needed for a POST with a JSON body)
local function httpFn() return (syn and syn.request) or http_request or request or (http and http.request) end
local function hwid() local ok, id = pcall(function() return (gethwid and gethwid()) or "unknown" end); return ok and tostring(id) or "unknown" end

-- POST the session token to /script. 2xx -> the raw Lua bundle; anything else -> nil, <server message>.
local function fetchScript(token)
	local fn = httpFn()
	if not fn then return nil, "your executor has no HTTP request function" end
	local ok, res = pcall(function()
		return fn({
			Url = AUTH_BASE .. "/script", Method = "POST",
			Headers = { ["Content-Type"] = "application/json" },
			Body = HttpService:JSONEncode({ session = token, hwid = hwid() }),
		})
	end)
	if not ok or type(res) ~= "table" then return nil, "network error reaching the server" end
	local code = res.StatusCode or res.status_code or 0
	if code >= 200 and code < 300 then return res.Body end
	local msg = "access denied (" .. tostring(code) .. ")"
	pcall(function() local d = HttpService:JSONDecode(res.Body); if d and d.error then msg = d.error end end)
	return nil, msg
end

local function runScript(token)
	local src, err = fetchScript(token)
	if not src or src == "" then
		warn("[Crypt] could not load the script: " .. tostring(err))
		pcall(function() game:GetService("StarterGui"):SetCore("SendNotification", { Title = "Crypt's Universal", Text = tostring(err), Duration = 8 }) end)
		return
	end
	local fn, lerr = loadstring(src, "=Crypt/bundle")
	if not fn then warn("[Crypt] the delivered script failed to compile: " .. tostring(lerr)); return end
	local ok, runErr = pcall(fn)
	if not ok then warn("[Crypt] the delivered script errored on run: " .. tostring(runErr)) end
end

-- fast path: a cached, locally-valid session that the Worker still accepts -> skip the sign-in card entirely
local cached = Crypt.Auth.loadSession()
if cached and cached.token and Crypt.Auth.validateSession() then
	runScript(cached.token)
else
	Crypt.buildAuthGate(function()
		local s = Crypt.Auth.session
		runScript(s and s.token)
	end)
end
