# 🔐 DocuVault — Secure Document Upload Portal

## What this app does
- Customers register with name, email & password
- They scan a QR code to set up 2FA (Google Authenticator / Authy)
- Every login requires email + password + 2FA code
- Each customer gets their own private folder on the server
- Documents are encrypted with AES-256 before storage
- You (admin) receive an email notification for every upload

## How to run

### 1. Install Node.js (if not already installed)
Download from: https://nodejs.org (choose LTS version)

### 2. Install dependencies
```
npm install
```

### 3. Set your admin email
Open `server.js` and find line:
```
const ADMIN_EMAIL = 'admin@yourcompany.com';
```
Change it to your real email address.

### 4. (Optional) Set up real email
Replace the ethereal test email section in server.js with your real SMTP:
```js
transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  auth: { user: 'your@gmail.com', pass: 'your-app-password' }
});
```

### 5. Start the app
```
npm start
```

### 6. Open in browser
Go to: http://localhost:3000

## Folder structure
```
docuvault/
├── server.js          ← Backend (Node.js)
├── public/
│   └── index.html     ← Frontend (the website)
├── uploads/
│   └── [user-id]/     ← Each customer's private folder
├── data/
│   └── users.json     ← Encrypted user accounts
└── package.json
```

## Security features
- Passwords hashed with bcrypt (industry standard)
- Sessions protected with JWT tokens (8-hour expiry)
- 2FA using TOTP (same standard as Google/banking apps)
- File metadata encrypted with AES-256
- Each customer can only see their own files
