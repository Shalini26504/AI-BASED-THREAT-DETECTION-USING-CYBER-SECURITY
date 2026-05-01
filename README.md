# 🛡️ GmailSec Real-Time Monitor v3.0

Monitors your REAL Gmail inbox for Google sign-in alert emails.
When a new device signs into your account → Twilio voice call + SMS + browser alert fires instantly.

---

## 📁 Folder Structure
```
gmailsec-realtime/
├── app.py              ← Flask app + Gmail polling + Twilio alerts
├── requirements.txt    ← Python dependencies
├── .env.example        ← Rename to .env and fill in credentials
├── templates/
│   ├── index.html      ← Google Sign-In landing page
│   └── dashboard.html  ← Live monitoring dashboard
└── logs/
    ├── events.json     ← Detected sign-in events
    └── alerts.json     ← Twilio call/SMS records
```

---

## ⚡ Quick Start (5 Steps)

### Step 1 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Set up Google OAuth2
1. Go to https://console.cloud.google.com
2. Create a project → Enable **Gmail API**
3. Go to APIs & Services → Credentials
4. Click **Create Credentials** → **OAuth 2.0 Client ID**
5. Application type: **Web application**
6. Add redirect URI: `http://localhost:5000/oauth/callback`
7. Copy Client ID and Client Secret

### Step 3 — Set up Twilio
1. Go to https://console.twilio.com
2. Get Account SID, Auth Token, and a phone number
3. Make sure your phone number is verified

### Step 4 — Configure .env
```bash
cp .env.example .env
# Edit .env with your credentials
```

### Step 5 — Run
```bash
python app.py
```
Open http://localhost:5000 → Click **Sign in with Google** → Done!

---

## 🔄 How It Works

```
You sign in with Google
        ↓
App gets permission to READ your Gmail (readonly)
        ↓
Background thread checks Gmail every 30 seconds
        ↓
Looks for emails from Google like:
  - "New sign-in to your Google Account"
  - "New device signed in"
  - "Critical security alert"
  - "Suspicious sign-in attempt"
        ↓
NEW email found?
        ↓
  ├── 📞 Twilio voice call to your mobile
  ├── 💬 Twilio SMS to your mobile
  ├── 🔊 Browser voice alert (Web Speech API)
  ├── 🔔 Browser push notification
  └── 📋 Logged to logs/events.json
```

---

## 🔐 Privacy
- Only reads Gmail metadata (subject, sender) — not email content
- Uses `gmail.readonly` OAuth scope
- No data is stored on any server — runs entirely on your machine
- Credentials stored only in your .env file

---

## 🧪 Testing
Click **⚡ TEST ALERT** button on dashboard to fire a test Twilio call+SMS
without waiting for a real sign-in event.
