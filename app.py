"""
GmailSec Real-Time Monitor
- OAuth2 Google login (real Gmail access)
- Polls Gmail every 30 seconds for new login alert emails
- AI detection: new device, new sign-in emails from Google
- Twilio voice call + SMS on detection
- Browser voice alert
"""

from flask import Flask, render_template, jsonify, request, redirect, session, url_for
import os, json, threading, time, re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "gmailsec_realtime_2024")

# ═══════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "YOUR_ACCOUNT_SID")
TWILIO_AUTH_TOKEN  = os.environ.get("TWILIO_AUTH_TOKEN",  "YOUR_AUTH_TOKEN")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER", "+1XXXXXXXXXX")
ALERT_PHONE        = os.environ.get("ALERT_PHONE_NUMBER", "+91XXXXXXXXXX")
TWILIO_ENABLED     = os.environ.get("TWILIO_ENABLED", "false").lower() == "true"

GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID",     "YOUR_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
GOOGLE_REDIRECT_URI  = "http://localhost:5000/oauth/callback"

POLL_INTERVAL = 30  # seconds between Gmail checks

# ═══════════════════════════════════════════════════════════
#  GLOBAL STATE  (in-memory, per session)
# ═══════════════════════════════════════════════════════════
monitor_state = {
    "running":       False,
    "email":         None,
    "events":        [],       # detected sign-in events
    "last_check":    None,
    "alerts_sent":   0,
    "status":        "idle",   # idle | monitoring | alert
    "seen_ids":      set(),    # Gmail message IDs already processed
    "credentials":   None,
}
state_lock = threading.Lock()

# ═══════════════════════════════════════════════════════════
#  GMAIL API — fetch security alert emails
# ═══════════════════════════════════════════════════════════
def get_gmail_service(credentials_dict):
    """Build Gmail API service from stored OAuth credentials."""
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    creds = Credentials(
        token=credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
    )
    return build("gmail", "v1", credentials=creds), creds


def fetch_new_signin_emails(credentials_dict):
    """
    Search Gmail inbox for NEW Google security alert emails
    that indicate a new sign-in or suspicious activity.
    Returns list of parsed events.
    """
    try:
        service, _ = get_gmail_service(credentials_dict)

        # Search for Google security/sign-in alert emails
        query = (
            'from:(no-reply@accounts.google.com OR '
            'no-reply@google.com) '
            'subject:("New sign-in" OR "new device" OR '
            '"security alert" OR "sign-in attempt" OR '
            '"Critical security alert") '
            'newer_than:1d'
        )

        result  = service.users().messages().list(userId="me", q=query, maxResults=10).execute()
        msgs    = result.get("messages", [])
        events  = []

        for m in msgs:
            msg_id = m["id"]
            with state_lock:
                if msg_id in monitor_state["seen_ids"]:
                    continue
                monitor_state["seen_ids"].add(msg_id)

            # Fetch full message
            full = service.users().messages().get(
                userId="me", id=msg_id, format="full"
            ).execute()

            event = parse_signin_email(full)
            if event:
                events.append(event)

        return events

    except Exception as e:
        print(f"[Gmail] Error: {e}")
        return []


def parse_signin_email(message):
    """Extract sign-in details from a Google security email."""
    headers = {h["name"]: h["value"] for h in message["payload"].get("headers", [])}
    subject = headers.get("Subject", "")
    date    = headers.get("Date", "")

    # Extract body text
    body = extract_body(message["payload"])

    # Determine event type
    event_type = "NEW_SIGNIN"
    severity   = "HIGH"

    subj_lower = subject.lower()
    if "critical" in subj_lower:
        event_type = "CRITICAL_ALERT"
        severity   = "CRITICAL"
    elif "new device" in subj_lower:
        event_type = "NEW_DEVICE"
        severity   = "HIGH"
    elif "sign-in attempt" in subj_lower or "suspicious" in subj_lower:
        event_type = "SUSPICIOUS_SIGNIN"
        severity   = "CRITICAL"
    elif "new sign-in" in subj_lower:
        event_type = "NEW_SIGNIN"
        severity   = "HIGH"

    # Extract device/app from body if present
    device = extract_device_from_body(body)
    app_name = extract_app_from_body(body)

    return {
        "id":          message["id"],
        "type":        event_type,
        "severity":    severity,
        "subject":     subject,
        "date":        date,
        "device":      device,
        "app":         app_name,
        "detected_at": datetime.utcnow().isoformat(),
        "raw_snippet": message.get("snippet", "")[:200],
    }


def extract_body(payload):
    """Recursively extract text body from Gmail payload."""
    import base64
    body = ""
    if "parts" in payload:
        for part in payload["parts"]:
            body += extract_body(part)
    elif payload.get("mimeType") in ("text/plain", "text/html"):
        data = payload.get("body", {}).get("data", "")
        if data:
            try:
                body = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
            except Exception:
                pass
    return body


def extract_device_from_body(body):
    """Try to extract device name from email body."""
    patterns = [
        r'Device:\s*(.+)',
        r'on\s+([\w\s]+(?:iPhone|Android|Windows|Mac|Linux|Chrome|Safari|Firefox)[^\n]*)',
        r'(iPhone|Android|Windows|MacBook|iPad|Linux)[^\n]*',
    ]
    for p in patterns:
        m = re.search(p, body, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:60]
    return "Unknown device"


def extract_app_from_body(body):
    """Try to extract app/browser from email body."""
    patterns = [
        r'App:\s*(.+)',
        r'(Chrome|Firefox|Safari|Edge|Gmail|Google)[^\n]{0,30}',
    ]
    for p in patterns:
        m = re.search(p, body, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:40]
    return "Unknown app"


# ═══════════════════════════════════════════════════════════
#  TWILIO ALERTS
# ═══════════════════════════════════════════════════════════
def fire_twilio_alerts(event, email):
    """Send both voice call and SMS for a detected sign-in event."""
    results = {}
    results["voice"] = twilio_voice_call(event, email)
    results["sms"]   = twilio_sms(event, email)
    return results


def twilio_voice_call(event, email):
    if not TWILIO_ENABLED:
        print("[Twilio] Voice call SKIPPED — TWILIO_ENABLED=false")
        return {"status": "skipped"}
    try:
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice" language="en-IN">
        Alert! Alert! This is G mail Sec Security Monitor.
        <break time="0.5s"/>
        A new sign in has been detected on your Google account
        {' '.join(email)}.
        <break time="0.5s"/>
        Event type: {event['type'].replace('_', ' ').title()}.
        Severity: {event['severity']}.
        <break time="0.5s"/>
        Device: {event.get('device', 'unknown device')}.
        <break time="0.8s"/>
        If this was not you, please secure your account immediately
        by going to myaccount dot google dot com and changing your password.
        <break time="0.5s"/>
        This is an automated alert from G mail Sec. Stay safe.
    </Say>
    <Pause length="1"/>
    <Say voice="alice">Goodbye.</Say>
</Response>"""

        call = client.calls.create(
            twiml=twiml,
            from_=TWILIO_FROM_NUMBER,
            to=ALERT_PHONE
        )
        print(f"[Twilio] ✅ Voice call → {ALERT_PHONE} | SID: {call.sid}")
        _save_alert_log("VOICE_CALL", email, event, call.sid)
        return {"status": "sent", "sid": call.sid, "to": ALERT_PHONE}

    except ImportError:
        return {"status": "error", "message": "Run: pip install twilio"}
    except Exception as e:
        print(f"[Twilio] ❌ Call error: {e}")
        return {"status": "error", "message": str(e)}


def twilio_sms(event, email):
    if not TWILIO_ENABLED:
        return {"status": "skipped"}
    try:
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        body = (
            f"🚨 GMAILSEC ALERT\n"
            f"Account: {email}\n"
            f"Event: {event['type'].replace('_',' ')}\n"
            f"Severity: {event['severity']}\n"
            f"Device: {event.get('device','unknown')}\n"
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC\n"
            f"Subject: {event.get('subject','')[:60]}\n"
            f"If not you → secure account NOW!"
        )

        msg = client.messages.create(body=body, from_=TWILIO_FROM_NUMBER, to=ALERT_PHONE)
        print(f"[Twilio] ✅ SMS → {ALERT_PHONE} | SID: {msg.sid}")
        _save_alert_log("SMS", email, event, msg.sid)
        return {"status": "sent", "sid": msg.sid, "to": ALERT_PHONE}

    except Exception as e:
        return {"status": "error", "message": str(e)}


def _save_alert_log(alert_type, email, event, sid):
    os.makedirs("logs", exist_ok=True)
    entry = {
        "timestamp":  datetime.utcnow().isoformat(),
        "type":       alert_type,
        "email":      email,
        "event_type": event.get("type"),
        "severity":   event.get("severity"),
        "sid":        sid
    }
    with open("logs/alerts.json", "a") as f:
        f.write(json.dumps(entry) + "\n")


# ═══════════════════════════════════════════════════════════
#  BACKGROUND MONITOR THREAD
# ═══════════════════════════════════════════════════════════
def monitor_loop():
    """
    Runs in background thread.
    Polls Gmail every POLL_INTERVAL seconds for new sign-in emails.
    """
    print("[Monitor] Background thread started")
    while True:
        with state_lock:
            running     = monitor_state["running"]
            credentials = monitor_state["credentials"]
            email       = monitor_state["email"]

        if not running or not credentials:
            time.sleep(5)
            continue

        try:
            with state_lock:
                monitor_state["last_check"] = datetime.utcnow().isoformat()
                monitor_state["status"]     = "monitoring"

            print(f"[Monitor] Checking Gmail for {email}...")
            new_events = fetch_new_signin_emails(credentials)

            if new_events:
                print(f"[Monitor] 🚨 {len(new_events)} new event(s) detected!")
                for ev in new_events:
                    # Fire Twilio alerts
                    alert_results = fire_twilio_alerts(ev, email)
                    ev["twilio"] = alert_results

                    with state_lock:
                        monitor_state["events"].insert(0, ev)
                        monitor_state["alerts_sent"] += 1
                        monitor_state["status"] = "alert"

                    # Save to log
                    os.makedirs("logs", exist_ok=True)
                    with open("logs/events.json", "a") as f:
                        f.write(json.dumps(ev) + "\n")
            else:
                with state_lock:
                    monitor_state["status"] = "monitoring"

        except Exception as e:
            print(f"[Monitor] Error: {e}")

        time.sleep(POLL_INTERVAL)


# Start background thread
monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
monitor_thread.start()


# ═══════════════════════════════════════════════════════════
#  OAUTH2 — Google Sign In
# ═══════════════════════════════════════════════════════════
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid",
    "email",
    "profile",
]

@app.route("/auth/google")
def auth_google():
    """Redirect to Google OAuth consent screen."""
    from urllib.parse import urlencode
    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(SCOPES),
        "access_type":   "offline",
        "prompt":        "consent",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return redirect(url)


@app.route("/oauth/callback")
def oauth_callback():
    """Handle Google OAuth callback, exchange code for tokens."""
    import requests as req

    code  = request.args.get("code")
    error = request.args.get("error")

    if error or not code:
        return redirect(url_for("index") + "?error=auth_failed")

    # Exchange code for tokens
    token_resp = req.post("https://oauth2.googleapis.com/token", data={
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "grant_type":    "authorization_code",
    })
    tokens = token_resp.json()

    if "error" in tokens:
        return redirect(url_for("index") + f"?error={tokens['error']}")

    # Get user info
    userinfo_resp = req.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    userinfo = userinfo_resp.json()
    email = userinfo.get("email", "unknown")

    credentials = {
        "token":         tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", ""),
    }

    # Start monitoring
    with state_lock:
        monitor_state["running"]     = True
        monitor_state["email"]       = email
        monitor_state["credentials"] = credentials
        monitor_state["events"]      = []
        monitor_state["seen_ids"]    = set()
        monitor_state["alerts_sent"] = 0
        monitor_state["status"]      = "monitoring"

    session["email"] = email
    print(f"[Auth] ✅ Authenticated as {email} — monitoring started")
    return redirect(url_for("dashboard"))


# ═══════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html",
                           google_configured=GOOGLE_CLIENT_ID != "YOUR_CLIENT_ID")


@app.route("/dashboard")
def dashboard():
    with state_lock:
        email = monitor_state["email"]
    if not email:
        return redirect(url_for("index"))
    return render_template("dashboard.html")


@app.route("/api/state")
def get_state():
    """Polling endpoint — frontend calls this every 5s."""
    with state_lock:
        return jsonify({
            "running":     monitor_state["running"],
            "email":       monitor_state["email"],
            "status":      monitor_state["status"],
            "last_check":  monitor_state["last_check"],
            "alerts_sent": monitor_state["alerts_sent"],
            "events":      monitor_state["events"][:20],
            "event_count": len(monitor_state["events"]),
            "twilio_enabled": TWILIO_ENABLED,
            "alert_phone": ALERT_PHONE,
        })


@app.route("/api/stop", methods=["POST"])
def stop_monitor():
    with state_lock:
        monitor_state["running"] = False
        monitor_state["status"]  = "idle"
    session.clear()
    return jsonify({"status": "stopped"})


@app.route("/api/test-alert", methods=["POST"])
def test_alert():
    """Fire a test Twilio call+SMS without needing a real Gmail event."""
    with state_lock:
        email = monitor_state["email"] or "test@gmail.com"

    fake_event = {
        "type":     "TEST_ALERT",
        "severity": "HIGH",
        "subject":  "Test — New sign-in to your Google Account",
        "device":   "Test Device",
        "app":      "GmailSec Test",
        "detected_at": datetime.utcnow().isoformat(),
    }
    results = fire_twilio_alerts(fake_event, email)
    return jsonify(results)


@app.route("/api/twilio-status")
def twilio_status():
    return jsonify({
        "enabled":    TWILIO_ENABLED,
        "configured": TWILIO_ACCOUNT_SID != "YOUR_ACCOUNT_SID",
        "alert_to":   ALERT_PHONE,
    })


@app.route("/api/status")
def status():
    return jsonify({"status": "online", "version": "3.0"})


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  GmailSec Real-Time Monitor v3.0")
    print("="*55)
    print(f"  Google OAuth  : {'✅ Configured' if GOOGLE_CLIENT_ID != 'YOUR_CLIENT_ID' else '⚠ Not configured'}")
    print(f"  Twilio        : {'✅ Enabled' if TWILIO_ENABLED else '⚠ Disabled'}")
    print(f"  Alert phone   : {ALERT_PHONE}")
    print(f"  Poll interval : {POLL_INTERVAL}s")
    print(f"  Open          : http://localhost:5000")
    print("="*55 + "\n")
    app.run(debug=True, port=5000, use_reloader=False)
