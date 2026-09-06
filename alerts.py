"""
alerts.py

Desktop + email notifications for high-severity detections (PORT SCAN / ALERT).
Uses plyer for cross-platform desktop notifications and smtplib for email.

Install: pip install plyer
"""

import smtplib
import time
from email.mime.text import MIMEText

try:
    from plyer import notification
except ImportError:
    notification = None

COOLDOWN_SECONDS = 30  # don't re-notify for the same key within this window
_last_notified = {}


def _should_notify(key):
    now = time.time()
    last = _last_notified.get(key, 0)
    if now - last >= COOLDOWN_SECONDS:
        _last_notified[key] = now
        return True
    return False


def send_desktop_alert(title, message, key=None):
    """Fire a native OS notification. `key` is used to rate-limit repeats."""
    if notification is None:
        return
    if key and not _should_notify(f"desktop:{key}"):
        return
    try:
        notification.notify(title=title, message=message, timeout=6)
    except Exception as e:
        print(f"[alerts] desktop notification failed: {e}")


def send_email_alert(smtp_config, subject, body, key=None):
    """
    smtp_config: dict with keys host, port, user, password, from_addr, to_addr
    (or None to disable email alerts entirely).
    """
    if not smtp_config:
        return
    if key and not _should_notify(f"email:{key}"):
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_config["from_addr"]
        msg["To"] = smtp_config["to_addr"]

        with smtplib.SMTP(smtp_config["host"], smtp_config["port"]) as server:
            server.starttls()
            server.login(smtp_config["user"], smtp_config["password"])
            server.sendmail(smtp_config["from_addr"], [smtp_config["to_addr"]], msg.as_string())
    except Exception as e:
        print(f"[alerts] email alert failed: {e}")