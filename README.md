# Crypt's Universal Script

A premium universal script for Roblox (Potassium). **Sign-in required** — run this one line in your executor:

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/Criptonized/crypts-universal/main/loader.lua"))()
```

You need an account:

- **Have a key?** Run the line, choose **Activate Key**, and create your account.
- **Returning?** Just **Log in** — a valid session skips the prompt.
- **Lost your password?** Use the one-time recovery code you saved at signup, or the email reset.

## What's in this repository

Only the **public sign-in loader** lives here (`loader.lua` + the account client `engine/auth.lua` and the sign-in
card `ui/auth_gate.lua`). The loader authenticates you, then the script itself is delivered **server-side, only for a
valid session** — it is never served from this repository. Access is revocable per account.
