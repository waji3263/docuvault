# DocuVault — Secure Client Document Portal
### Fast Professional Services Inc.

A secure, encrypted document management portal for tax service clients.

## Features
- 🔒 AES-256 encrypted document storage
- 📱 Google Authenticator 2FA (clients + admins)
- 👥 Three-tier admin roles (Super Admin, Admin, Limited Admin)
- 📧 Email notifications via Brevo API
- 📊 Bulk CSV/Excel client import
- 🧹 Automatic document retention/cleanup
- 💬 Real-time admin-client messaging
- 📋 Document request checklists
- 📁 Document versioning & status flags
- 📋 Full system audit log

## Live URL
https://portal.fastpro.tax

## Tech Stack
- **Backend:** Node.js / Express
- **Frontend:** Plain HTML/CSS/JS
- **Storage:** Flat JSON files (AES-256 encrypted)
- **Email:** Brevo HTTP API
- **Auth:** JWT + TOTP (speakeasy)
- **Hosting:** GoDaddy Node.js

## Deployment
This repository is connected to GoDaddy for automatic deployment.
Every push to the `main` branch automatically deploys to production.

## Environment Variables (set in GoDaddy Secrets)
| Variable | Purpose |
|---|---|
| `BASE_URL` | Live site URL (https://portal.fastpro.tax) |
| `JWT_SECRET` | Secret key for JWT tokens |
| `ENCRYPTION_KEY` | Key for AES-256 document encryption |

## ⚠️ Security Notes
- Never commit `.env` files
- Never commit `data/users.json` or `data/admins.json`
- Never commit files in `uploads/`
- All sensitive config is stored in GoDaddy environment secrets
