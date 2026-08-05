"""Alert notification delivery for srecon (stdlib only).

Delivery adapters used by ``python3 -m srecon alerts --notify``. Everything is
pure stdlib (``urllib`` / ``smtplib`` / ``email``) and every adapter catches
its own errors and returns ``{"ok": bool, "error": str|None}`` — nothing here
ever raises, so a broken webhook URL or SMTP server can never take down the
CLI.

Channels
--------
* ``webhook`` — HTTP POST webhook (Slack / Discord / plain JSON endpoint).
  The payload shape is selected by ``?kind=slack|discord|generic`` in the URL
  query string and defaults to ``generic``:

  * ``generic``: raw JSON ``{alerts: [...], generated_at, count}``
  * ``slack``:   ``{text: summary, attachments: [{color, title, text}]}``
  * ``discord``: ``{embeds: [{title, color, description}]}``

* ``email`` — plain-text SMTP message (STARTTLS when available, optional
  login), with a compact summary line plus one line per alert.

Config file shape (JSON)::

    {
      "webhook": "https://hooks.slack.com/services/T..?kind=slack",
      "smtp": {
        "host": "smtp.example.com", "port": 587,
        "from": "srecon@example.com",
        "to": ["ops@example.com"],
        "user": "...", "password": "...",
        "subject": "srecon alerts"
      }
    }

``deliver(alerts, config)`` dispatches to whichever channels are configured
and returns per-channel ``{ok, error}``.
"""

import json
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate

# ---------------------------------------------------------------------------
# alert rendering helpers (shared by webhook + email payloads)
# ---------------------------------------------------------------------------

_SLACK_COLORS = {"high": "#D93025", "medium": "#E67E22", "low": "#95A5A6"}
_DISCORD_COLORS = {"high": 0xD93025, "medium": 0xE67E22, "low": 0x95A5A6}
_KINDS = ("slack", "discord", "generic")


def _describe(alert):
    """Compact one-line change description for an alert dict."""
    old, new = alert.get("old"), alert.get("new")
    if old is None:
        return "appeared as %s" % (new or "present")
    return "%s -> %s" % (old or "-", new or "-")


def _line(alert):
    """One line per alert, e.g. '[HIGH] VERDICT_FLIP 1.2.3.4:8000: A -> B'."""
    return "[%s] %s %s: %s" % (
        str(alert.get("severity") or "?").upper(),
        alert.get("kind"),
        alert.get("target"),
        _describe(alert))


def _summary(alerts):
    """e.g. 'srecon: 3 change alert(s) for scan 7'."""
    base = "srecon: %d change alert(s)" % len(alerts)
    scan = alerts[0].get("scan_id_b") if alerts else None
    if scan is not None:
        base += " for scan %s" % scan
    return base


def _payload(alerts, kind, generated_at):
    """Shape the webhook body for the requested channel kind."""
    if kind == "slack":
        return {
            "text": _summary(alerts),
            "attachments": [
                {
                    "color": _SLACK_COLORS.get(a.get("severity"), "#95A5A6"),
                    "title": "[%s] %s %s" % (
                        str(a.get("severity") or "?").upper(),
                        a.get("kind"), a.get("target")),
                    "text": _describe(a),
                }
                for a in alerts
            ],
        }
    if kind == "discord":
        return {
            "embeds": [
                {
                    "title": _summary(alerts),
                    "color": (_DISCORD_COLORS.get(alerts[0].get("severity"))
                              if alerts else 0x95A5A6),
                    "description": "\n".join(_line(a) for a in alerts)
                                   or "no alerts",
                }
            ],
        }
    # generic: raw machine payload
    return {"alerts": alerts, "generated_at": generated_at, "count": len(alerts)}


def _kind_from_url(url, default):
    """Read ?kind=slack|discord|generic from the URL, else ``default``."""
    try:
        query = urllib.parse.urlparse(url).query
        kinds = urllib.parse.parse_qs(query).get("kind")
    except ValueError:
        return default
    if kinds and kinds[0] in _KINDS:
        return kinds[0]
    return default


# ---------------------------------------------------------------------------
# webhook adapter
# ---------------------------------------------------------------------------

def notify_webhook(url, alerts, kind="generic", timeout=10):
    """POST an alert payload to a webhook URL. Never raises.

    Returns ``{"ok": bool, "error": str|None}``. Any URL/connection/HTTP
    error is caught and reported in ``error``.
    """
    try:
        resolved = _kind_from_url(url, kind)
        generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        data = json.dumps(_payload(alerts, resolved, generated_at)).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        return {"ok": True, "error": None}
    except Exception as e:  # noqa: BLE001 - adapters never raise
        if isinstance(e, urllib.error.HTTPError):
            try:
                e.close()  # HTTPError is a file-like response; release it
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}


# ---------------------------------------------------------------------------
# email adapter
# ---------------------------------------------------------------------------

def build_email_subject(alerts):
    """Default subject line for an alert batch."""
    base = "srecon: %d change alert(s)" % len(alerts)
    scan = alerts[0].get("scan_id_b") if alerts else None
    if scan is not None:
        base += " for scan %s" % scan
    return base


def build_email_body(alerts):
    """Compact plain-text body: summary line + one line per alert."""
    lines = [_summary(alerts), ""]
    lines.extend(_line(a) for a in alerts)
    return "\n".join(lines)


def notify_email(smtp_host, from_addr, to_addrs, subject, body,
                 user=None, password=None, port=None, use_tls=True,
                 timeout=10):
    """Send a plain-text alert email over SMTP. Never raises.

    Returns ``{"ok": bool, "error": str|None}``. Uses ``SMTP_SSL`` when
    ``port == 465``; otherwise ``SMTP`` with best-effort STARTTLS (a server
    that does not offer STARTTLS is used plaintext). ``user``/``password``
    trigger an optional LOGIN.
    """
    try:
        if isinstance(to_addrs, str):
            to_addrs = [to_addrs]
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg.set_content(body)

        if port is None:
            port = 465 if not use_tls else 587
        if port == 465:
            smtp = smtplib.SMTP_SSL(smtp_host, port, timeout=timeout)
        else:
            smtp = smtplib.SMTP(smtp_host, port, timeout=timeout)
            if use_tls:
                try:
                    smtp.starttls()
                except Exception:  # noqa: BLE001 - fall back to plaintext
                    pass
        try:
            if user:
                smtp.login(user, password or "")
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except Exception:  # noqa: BLE001 - best-effort disconnect
                pass
        return {"ok": True, "error": None}
    except Exception as e:  # noqa: BLE001 - adapters never raise
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}


# ---------------------------------------------------------------------------
# dispatcher
# ---------------------------------------------------------------------------

def deliver(alerts, config):
    """Deliver ``alerts`` via every channel configured in ``config``.

    ``config`` is a dict: ``{"webhook": url, "smtp": {...}}``. Each present
    channel is attempted; the result is ``{channel: {"ok": bool, "error": ...}}``
    for the channels that exist in the config. Never raises.
    """
    results = {}
    if not isinstance(config, dict):
        return results

    webhook_url = config.get("webhook")
    if webhook_url:
        results["webhook"] = notify_webhook(webhook_url, alerts)

    smtp_cfg = config.get("smtp")
    if smtp_cfg:
        host = smtp_cfg.get("host")
        from_addr = smtp_cfg.get("from")
        to_addrs = smtp_cfg.get("to")
        if not host or not from_addr or not to_addrs:
            results["email"] = {
                "ok": False,
                "error": "smtp config requires host, from and to",
            }
        else:
            subject = smtp_cfg.get("subject") or build_email_subject(alerts)
            results["email"] = notify_email(
                host, from_addr, to_addrs, subject, build_email_body(alerts),
                user=smtp_cfg.get("user"), password=smtp_cfg.get("password"),
                port=smtp_cfg.get("port"), use_tls=smtp_cfg.get("use_tls", True))
    return results
