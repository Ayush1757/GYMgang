# login-app

This is a simple gym login app.

To enable administrator registration you must provide an `ADMIN_KEY` value. You can set it in your environment or create a `.env` file in the project root.

Quick start (PowerShell):

```powershell
# set ADMIN_KEY for current session and start server
$env:ADMIN_KEY = "your_admin_key_here"
npm install
node server.js
```

Or create a `.env` file (recommended for local development):

```
ADMIN_KEY=your_admin_key_here
```

The server already uses `dotenv` to load a `.env` file automatically. After registering an admin with the same key, log in as that admin to access admin-only features.
