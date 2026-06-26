-- ui/auth_gate.lua -- Crypt.buildAuthGate(onPass): the pre-menu sign-in gate (distribution Phase 1).
-- ============================================================================
-- A self-contained ScreenGui shown BEFORE the main menu when getgenv().Crypt_RequireAuth is set. Three modes:
-- Login (username/password) · Activate Key (1-time key -> create account) · Recover (recovery code / email).
-- Drives Crypt.Auth (which falls back to its mock backend offline, so the whole flow works without the Worker).
-- On success it destroys itself and calls onPass() -> the menu builds. Raw Instances + Theme accent so it has no
-- dependency on the (not-yet-built) main window. Untested in-game (like all UI); compile-validated.
-- ============================================================================
return function(Crypt)
	local Players = game:GetService("Players")
	local lp = Players.LocalPlayer
	local T = Crypt.Theme or {}
	local ACCENT = T.accent or Color3.fromRGB(124, 92, 255)
	local CARD, FIELD = Color3.fromRGB(28, 28, 38), Color3.fromRGB(40, 40, 52)
	local TXT, DIM = Color3.fromRGB(235, 235, 245), Color3.fromRGB(150, 150, 165)
	local GOOD, BAD = Color3.fromRGB(74, 222, 128), Color3.fromRGB(248, 113, 113)
	local FONT = Enum.Font.Gotham

	local function corner(o, r) local c = Instance.new("UICorner"); c.CornerRadius = UDim.new(0, r or 8); c.Parent = o end
	local function listLayout(o) local l = Instance.new("UIListLayout"); l.Padding = UDim.new(0, 8); l.SortOrder = Enum.SortOrder.LayoutOrder; l.Parent = o; return l end

	function Crypt.buildAuthGate(onPass)
		local sg = Instance.new("ScreenGui")
		sg.Name = "CryptAuthGate"; sg.ResetOnSpawn = false; sg.IgnoreGuiInset = true; sg.DisplayOrder = 9999; sg.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
		pcall(function() sg.Parent = (gethui and gethui()) or lp:WaitForChild("PlayerGui") end)

		-- while this modal is open, disable the hotbar so number keys you type don't equip tools (restored on exit).
		local SG = game:GetService("StarterGui")
		local prevBackpack = true
		pcall(function() prevBackpack = SG:GetCoreGuiEnabled(Enum.CoreGuiType.Backpack) end)
		pcall(function() SG:SetCoreGuiEnabled(Enum.CoreGuiType.Backpack, false) end)

		local dim = Instance.new("Frame"); dim.Size = UDim2.fromScale(1, 1); dim.BackgroundColor3 = Color3.new(0, 0, 0); dim.BackgroundTransparency = 0.35; dim.BorderSizePixel = 0; dim.Parent = sg

		local card = Instance.new("Frame"); card.Size = UDim2.fromOffset(360, 430); card.Position = UDim2.fromScale(0.5, 0.5); card.AnchorPoint = Vector2.new(0.5, 0.5); card.BackgroundColor3 = CARD; card.BorderSizePixel = 0; card.Parent = sg; corner(card, 12)
		local bar = Instance.new("Frame"); bar.Size = UDim2.new(1, 0, 0, 4); bar.BackgroundColor3 = ACCENT; bar.BorderSizePixel = 0; bar.Parent = card; corner(bar, 4)

		local title = Instance.new("TextLabel"); title.BackgroundTransparency = 1; title.Position = UDim2.fromOffset(20, 16); title.Size = UDim2.new(1, -40, 0, 26); title.Font = Enum.Font.GothamBold; title.TextSize = 20; title.TextColor3 = TXT; title.TextXAlignment = Enum.TextXAlignment.Left; title.Text = "Crypt's Universal"; title.Parent = card
		local sub = Instance.new("TextLabel"); sub.BackgroundTransparency = 1; sub.Position = UDim2.fromOffset(20, 42); sub.Size = UDim2.new(1, -40, 0, 18); sub.Font = FONT; sub.TextSize = 13; sub.TextColor3 = DIM; sub.TextXAlignment = Enum.TextXAlignment.Left; sub.Text = "Sign in to continue"; sub.Parent = card

		local tabs = Instance.new("Frame"); tabs.BackgroundTransparency = 1; tabs.Position = UDim2.fromOffset(20, 70); tabs.Size = UDim2.new(1, -40, 0, 30); tabs.Parent = card
		local tl = Instance.new("UIListLayout"); tl.FillDirection = Enum.FillDirection.Horizontal; tl.Padding = UDim.new(0, 6); tl.Parent = tabs

		local content = Instance.new("ScrollingFrame"); content.BackgroundTransparency = 1; content.BorderSizePixel = 0; content.ScrollBarThickness = 3; content.ScrollBarImageColor3 = ACCENT; content.AutomaticCanvasSize = Enum.AutomaticSize.Y; content.CanvasSize = UDim2.new(); content.Position = UDim2.fromOffset(20, 110); content.Size = UDim2.new(1, -40, 1, -160); content.Parent = card

		local status = Instance.new("TextLabel"); status.BackgroundTransparency = 1; status.AnchorPoint = Vector2.new(0, 1); status.Position = UDim2.new(0, 20, 1, -14); status.Size = UDim2.new(1, -40, 0, 34); status.Font = FONT; status.TextSize = 12; status.TextColor3 = DIM; status.TextWrapped = true; status.TextYAlignment = Enum.TextYAlignment.Bottom; status.TextXAlignment = Enum.TextXAlignment.Left; status.Text = ""; status.Parent = card
		local function setStatus(msg, good) status.Text = msg or ""; status.TextColor3 = (good == true and GOOD) or (good == false and BAD) or DIM end

		local function clearContent() for _, c in ipairs(content:GetChildren()) do c:Destroy() end; listLayout(content) end
		local function field(placeholder)
			local box = Instance.new("TextBox"); box.Size = UDim2.new(1, 0, 0, 34); box.BackgroundColor3 = FIELD; box.BorderSizePixel = 0; box.Font = FONT; box.TextSize = 14; box.TextColor3 = TXT; box.PlaceholderText = placeholder; box.PlaceholderColor3 = DIM; box.Text = ""; box.ClearTextOnFocus = false; box.TextXAlignment = Enum.TextXAlignment.Left; box.Parent = content; corner(box, 6)
			local p = Instance.new("UIPadding"); p.PaddingLeft = UDim.new(0, 8); p.PaddingRight = UDim.new(0, 8); p.Parent = box
			return box
		end
		local function note(text) local l = Instance.new("TextLabel"); l.BackgroundTransparency = 1; l.Size = UDim2.new(1, 0, 0, 30); l.Font = FONT; l.TextSize = 12; l.TextColor3 = DIM; l.TextWrapped = true; l.TextXAlignment = Enum.TextXAlignment.Left; l.Text = text; l.Parent = content; return l end
		local function button(text, cb) local b = Instance.new("TextButton"); b.Size = UDim2.new(1, 0, 0, 36); b.BackgroundColor3 = ACCENT; b.BorderSizePixel = 0; b.Font = Enum.Font.GothamBold; b.TextSize = 14; b.TextColor3 = Color3.new(1, 1, 1); b.AutoButtonColor = true; b.Text = text; b.Parent = content; corner(b, 6); b.MouseButton1Click:Connect(function() pcall(cb) end); return b end
		local function passGate() pcall(function() SG:SetCoreGuiEnabled(Enum.CoreGuiType.Backpack, prevBackpack) end); pcall(function() sg:Destroy() end); pcall(onPass) end
		-- after registration, force a deliberate "save your recovery code" step (it's shown only once).
		local function showRecoveryCode(code)
			clearContent()
			note("SAVE THIS RECOVERY CODE -- shown only once. It resets your password if you forget it (no email needed).")
			local box = field(""); box.Text = tostring(code or ""); box.TextEditable = false; box.TextSize = 16; box.Font = Enum.Font.GothamBold; box.TextXAlignment = Enum.TextXAlignment.Center
			button("Copy code", function()
				if type(setclipboard) == "function" then pcall(function() setclipboard(tostring(code or "")) end); setStatus("Copied to clipboard.", true)
				else setStatus("Select the code above and copy it manually.", nil) end
			end)
			button("I've saved it -- continue", function() passGate() end)
		end

		local renderers = {}
		renderers.login = function()
			clearContent()
			local u = field("Username"); local p = field("Password")
			button("Log in", function()
				setStatus("Signing in...")
				local ok, d = Crypt.Auth.login(u.Text, p.Text)
				if ok then setStatus("Welcome back, " .. (d.username or u.Text) .. "!", true); task.wait(0.4); passGate() else setStatus((d and d.error) or "Login failed.", false) end
			end)
			note("No account? Activate a 1-time key to create one.")
		end
		renderers.activate = function()
			clearContent()
			local k = field("CRYPT-XXXXX-XXXXX-X")
			button("Activate key", function()
				if not Crypt.Auth.validKeyFormat(k.Text) then setStatus("That doesn't look like a valid key.", false); return end
				setStatus("Activating...")
				local ok, at = Crypt.Auth.activate(k.Text)
				if not ok then setStatus(tostring(at) or "Activation failed.", false); return end
				clearContent()
				local u = field("Choose a username"); local p = field("Choose a password"); local e = field("Email (optional, for recovery)")
				button("Create account", function()
					local uok, ur = Crypt.Auth.validUsername(u.Text); if not uok then setStatus(ur, false); return end
					local pok = Crypt.Auth.validPassword(p.Text); if not pok then setStatus("Password must be at least 8 characters.", false); return end
					setStatus("Creating account...")
					local rok, d = Crypt.Auth.register(at, u.Text, p.Text, (e.Text ~= "" and e.Text) or nil)
					if rok then showRecoveryCode(d.recoveryCode) else setStatus((d and d.error) or "Could not create account.", false) end
				end)
				setStatus("Key accepted -- create your account.", true)
			end)
			if not (getgenv and getgenv().Crypt_AuthBase) and Crypt.Auth._mock and Crypt.Auth._mock.demoKeys[1] then
				note("Offline demo -- try key: " .. Crypt.Auth._mock.demoKeys[1])
			end
		end
		renderers.recover = function()
			local showReset, showForgotUser
			showReset = function()
				clearContent()
				note("Reset your password. Email yourself a code, or use the one-time recovery code from signup.")
				local idf = field("Username or email")
				button("Email me a reset code", function()
					local ok, d = Crypt.Auth.forgot(idf.Text)
					local extra = (ok and d and d.devCode) and ("  (offline code: " .. tostring(d.devCode) .. ")") or ""
					setStatus(ok and ("If that account exists, a reset code was emailed." .. extra) or ((d and d.error) or "Could not send."), ok == true)
				end)
				local cf = field("Reset code or recovery code"); local np = field("New password")
				button("Reset password", function()
					if not Crypt.Auth.validPassword(np.Text) then setStatus("New password must be at least 8 characters.", false); return end
					local ok, d = Crypt.Auth.reset(cf.Text, np.Text)
					if ok then setStatus("Password reset -- now log in.", true); task.wait(0.6); renderers.login() else setStatus((d and d.error) or "Reset failed.", false) end
				end)
				button("Forgot your username instead?", function() showForgotUser() end)
			end
			showForgotUser = function()
				clearContent()
				note("Forgot your username? Enter your email and we'll send it.")
				local ef = field("Email")
				button("Email me my username", function()
					if not Crypt.Auth.validEmail(ef.Text) then setStatus("Enter a valid email.", false); return end
					local ok, d = Crypt.Auth.recoverUsername(ef.Text)
					local extra = (ok and d and d.devUsernames) and ("  (offline: " .. table.concat(d.devUsernames, ", ") .. ")") or ""
					setStatus(ok and ("If that email is on file, your username was sent." .. extra) or ((d and d.error) or "Could not send."), ok == true)
				end)
				button("Back to password reset", function() showReset() end)
			end
			showReset()
		end

		local tabBtns = {}
		local function selectTab(m) for kk, b in pairs(tabBtns) do b.BackgroundColor3 = (kk == m) and ACCENT or FIELD end; setStatus(""); renderers[m]() end
		for _, t in ipairs({ { "login", "Login" }, { "activate", "Activate Key" }, { "recover", "Recover" } }) do
			local b = Instance.new("TextButton"); b.AutomaticSize = Enum.AutomaticSize.X; b.Size = UDim2.new(0, 0, 1, 0); b.BackgroundColor3 = FIELD; b.BorderSizePixel = 0; b.Font = FONT; b.TextSize = 13; b.TextColor3 = TXT; b.Text = "  " .. t[2] .. "  "; b.Parent = tabs; corner(b, 6)
			tabBtns[t[1]] = b
			local key = t[1]
			b.MouseButton1Click:Connect(function() selectTab(key) end)
		end
		selectTab("login")
		return sg
	end
end
