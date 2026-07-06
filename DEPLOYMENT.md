# 🚀 Deploying DocuVault on Hostinger (Cloud Startup)

## Your Setup
- **Company:** Fast Professional Services Inc.
- **Live URL:** https://portal.fastprofessional.com  (or your chosen subdomain)
- **Plan:** Hostinger Cloud Startup

---

## Step 1 — Create a subdomain in hPanel (recommended)

1. Log into **hpanel.hostinger.com**
2. Go to **Domains** → your domain `fastprofessional.com`
3. Click **Subdomains** → **Create subdomain**
4. Enter: `portal`  →  this creates `portal.fastprofessional.com`

---

## Step 2 — Add a Node.js App

1. In hPanel → **Websites** → **Add Website**
2. Choose **Node.js App**
3. Select domain: `portal.fastprofessional.com`
4. Upload this ZIP file: `docuvault-hostinger.zip`
5. Set **Entry file**: `server.js`
6. Set **Node.js version**: `18` or higher
7. Click **Deploy**

---

## Step 3 — Set Environment Variables

In your Node.js app settings on hPanel, add these:

| Variable        | Value                                    |
|-----------------|------------------------------------------|
| `BASE_URL`      | `https://portal.fastprofessional.com`    |
| `JWT_SECRET`    | (generate below)                         |
| `ENCRYPTION_KEY`| (generate below)                         |

**Generate secure random strings** — run this in your terminal (PowerShell or cmd):
```
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Run it twice — once for JWT_SECRET, once for ENCRYPTION_KEY.

---

## Step 4 — First Login After Going Live

1. Visit: `https://portal.fastprofessional.com/admin.html`
2. Login: Name = `Super Admin` · Password = `Admin@1234`
3. **Immediately** go to **👑 Admin Accounts** → reset your password
4. Go to **⚙️ Email & Agreement** → enter SMTP:
   - Host: `cp.ylinxhost.com`
   - Port: `587`
   - Email: `admin@fastprofessional.com`
   - Password: your email password
5. Click **Save** → **Send Test Email** to confirm it works

---

## Step 5 — Set Document Retention

In Admin → **⚙️ Email & Agreement** → **Document Auto-Delete**:
- Set to `72` hours (or your preferred retention period)
- Click Save

---

## Important Notes

- **HTTPS/SSL**: Hostinger provides free SSL automatically — no extra setup needed
- **Data storage**: All data lives in the `data/` folder on your server
- **Uploads**: Stored in the `uploads/` folder — automatically created on first run
- **Backups**: Download your `data/` folder regularly from hPanel File Manager

---

## After Deployment — Mobile App

Once the portal is live, the React Native mobile app (Android + iPhone) will be
built to connect to `https://portal.fastprofessional.com` automatically.
