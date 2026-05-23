from __future__ import annotations

"""Email Forensics Cell — parse .eml files, analyze headers, detect phishing, parse mbox.

All tools use Python stdlib (email, mailbox, hashlib) — zero external dependencies.
"""

import email
import hashlib
import mailbox
import re
from datetime import datetime
from email.policy import default
from pathlib import Path
from typing import Any

from forhacker.plugin.base import BasePlugin, Tool


class EmailForensicsPlugin(BasePlugin):
    name = "email-forensics"
    version = "0.1.0"
    domain = "forensics"
    risk_levels = {
        "parse_eml": "LOW",
        "extract_email_headers": "LOW",
        "analyze_attachments": "LOW",
        "detect_phishing_indicators": "LOW",
        "parse_mbox": "LOW",
    }

    def register_tools(self) -> list[Tool]:
        return [
            Tool(
                name="parse_eml",
                description="Parse a .eml file — headers, body, and attachment metadata",
                domain="forensics",
                risk_level="LOW",
                applicable_extensions=(".eml",),
            ),
            Tool(
                name="extract_email_headers",
                description="Extract and parse email authentication headers",
                domain="forensics",
                risk_level="LOW",
                applicable_extensions=(".eml",),
            ),
            Tool(
                name="analyze_attachments",
                description="List and hash all attachments in an email",
                domain="forensics",
                risk_level="LOW",
                applicable_extensions=(".eml",),
            ),
            Tool(
                name="detect_phishing_indicators",
                description="Check for common phishing indicators in an email",
                domain="forensics",
                risk_level="LOW",
                applicable_extensions=(".eml",),
            ),
            Tool(
                name="parse_mbox",
                description="Parse an mbox format mail archive and list messages",
                domain="forensics",
                risk_level="LOW",
                applicable_extensions=(".mbox",),
            ),
        ]


def _make_email_obj(target: str):
    """Parse an .eml file and return email.message.EmailMessage."""
    path = Path(target)
    if not path.exists():
        return None, {"error": f"File not found: {target}"}
    try:
        with path.open("rb") as fh:
            msg = email.message_from_binary_file(fh, policy=default)
        return msg, None
    except Exception as e:
        return None, {"error": f"Failed to parse email: {e}"}


def _format_date(dt) -> str:
    """Format a datetime object to ISO string."""
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def run_parse_eml(target: str) -> dict[str, Any]:
    """Parse a single .eml file and return structured data."""
    msg, error = _make_email_obj(target)
    if error:
        return error

    attachments = []
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disp = str(part.get_content_disposition() or "")
            if "attachment" in disp:
                payload = part.get_payload(decode=True)
                sha = hashlib.sha256(payload).hexdigest() if payload else ""
                attachments.append(
                    {
                        "filename": part.get_filename() or "unnamed",
                        "content_type": content_type,
                        "size": len(payload) if payload else 0,
                        "sha256": sha,
                    }
                )
            elif content_type == "text/plain":
                try:
                    body_text = part.get_content()
                except Exception:
                    body_text = str(part.get_payload(decode=True) or b"", errors="replace")
            elif content_type == "text/html":
                try:
                    body_html = part.get_content()
                except Exception:
                    body_html = str(part.get_payload(decode=True) or b"", errors="replace")
    else:
        if msg.get_content_type() == "text/html":
            body_html = str(msg.get_content())
        else:
            body_text = str(msg.get_content())

    return {
        "file": str(Path(target).absolute()),
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "attachment_count": len(attachments),
        "attachments": attachments,
        "body_text_preview": body_text[:500] if body_text else "",
        "has_html_body": bool(body_html),
    }


def run_extract_email_headers(target: str) -> dict[str, Any]:
    """Extract and analyze all email headers for forensic investigation."""
    msg, error = _make_email_obj(target)
    if error:
        return error

    headers: dict[str, str] = {}
    for key, value in msg.items():
        headers[key.lower()] = value

    received = [v for k, v in headers.items() if k == "received"]
    auth_results = headers.get("authentication-results", "")

    spf_pass = "spf=pass" in auth_results.lower()
    dkim_pass = "dkim=pass" in auth_results.lower()
    dmarc_pass = "dmarc=pass" in auth_results.lower()

    return {
        "file": str(Path(target).absolute()),
        "subject": headers.get("subject", ""),
        "from": headers.get("from", ""),
        "to": headers.get("to", ""),
        "cc": headers.get("cc", ""),
        "date": headers.get("date", ""),
        "message_id": headers.get("message-id", ""),
        "return_path": headers.get("return-path", ""),
        "reply_to": headers.get("reply-to", ""),
        "received_count": len(received),
        "received_chain": received[:10],
        "content_type": headers.get("content-type", ""),
        "user_agent": headers.get("user-agent", headers.get("x-mailer", "")),
        "auth": {
            "spf": "pass" if spf_pass else ("fail" if "spf=fail" in auth_results.lower() else "unknown"),
            "dkim": "pass" if dkim_pass else ("fail" if "dkim=fail" in auth_results.lower() else "unknown"),
            "dmarc": "pass" if dmarc_pass else ("fail" if "dmarc=fail" in auth_results.lower() else "unknown"),
        },
    }


def run_analyze_attachments(target: str) -> dict[str, Any]:
    """List and hash all attachments in an email file."""
    msg, error = _make_email_obj(target)
    if error:
        return error

    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get_content_disposition() or "")
            if "attachment" in disp:
                payload = part.get_payload(decode=True)
                raw_bytes = payload if payload else b""
                attachments.append(
                    {
                        "filename": part.get_filename() or "unnamed",
                        "content_type": part.get_content_type(),
                        "size": len(raw_bytes),
                        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                        "md5": hashlib.md5(raw_bytes).hexdigest(),
                    }
                )

    return {
        "file": str(Path(target).absolute()),
        "attachment_count": len(attachments),
        "attachments": attachments,
    }


_PHISHING_CHECKS = [
    (
        "mismatched_from",
        lambda h, b, d: (
            h.get("from", "")
            and h.get("return-path", "")
            and _extract_domain(h.get("from", "")) != _extract_domain(h.get("return-path", ""))
        ),
    ),
    ("suspicious_urls", lambda h, b, d: bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", b))),
    (
        "urgent_language",
        lambda h, b, d: bool(
            re.search(r"(urgent|immediately|account.*suspend|verify.*account|click.*here.*confirm)", b, re.IGNORECASE)
        ),
    ),
    (
        "shortened_urls",
        lambda h, b, d: bool(re.search(r"https?://(bit\.ly|tinyurl\.com|t\.co|ow\.ly|goo\.gl|is\.gd|buff\.ly)", b)),
    ),
    ("spf_fail", lambda h, b, d: "spf=fail" in d.get("auth_results", "").lower()),
    ("dkim_fail", lambda h, b, d: "dkim=fail" in d.get("auth_results", "").lower()),
    (
        "suspicious_subject",
        lambda h, b, d: bool(
            re.search(
                r"(free.*money|won.*prize|inheritance|lottery|claim.*now|act.*now)", h.get("subject", ""), re.IGNORECASE
            )
        ),
    ),
    (
        "generic_greeting",
        lambda h, b, d: bool(
            re.search(r"^(dear\s+(sir|customer|user|client|member|valued))", b, re.IGNORECASE | re.MULTILINE)
        ),
    ),
]


def _extract_domain(email_addr: str) -> str:
    """Extract domain from an email address."""
    match = re.search(r"@([^>\s@]+)", email_addr)
    return match.group(1).lower() if match else ""


def run_detect_phishing_indicators(target: str) -> dict[str, Any]:
    """Check an email for common phishing indicators."""
    msg, error = _make_email_obj(target)
    if error:
        return error

    headers: dict[str, str] = {}
    for key, value in msg.items():
        headers[key.lower()] = value

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body = part.get_content()
                except Exception:
                    body = str(part.get_payload(decode=True) or b"", errors="replace")
                break
    else:
        body = str(msg.get_content())

    auth_results = headers.get("authentication-results", "")
    domain_data = {"auth_results": auth_results}

    indicators = []
    for name, check_fn in _PHISHING_CHECKS:
        if check_fn(headers, body, domain_data):
            indicators.append(name)

    risk_score = len(indicators)
    risk_level = "LOW"
    if risk_score >= 4:
        risk_level = "HIGH"
    elif risk_score >= 2:
        risk_level = "MEDIUM"

    return {
        "file": str(Path(target).absolute()),
        "subject": headers.get("subject", ""),
        "from": headers.get("from", ""),
        "indicators_found": indicators,
        "indicator_count": risk_score,
        "risk_level": risk_level,
        "checked_domains": {
            "from_domain": _extract_domain(headers.get("from", "")),
            "return_path_domain": _extract_domain(headers.get("return-path", "")),
            "reply_to_domain": _extract_domain(headers.get("reply-to", "")),
        },
    }


def run_parse_mbox(target: str, max_messages: int = 200) -> dict[str, Any]:
    """Parse an mbox format mail archive file."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}

    try:
        mbox = mailbox.mbox(str(path))
    except Exception as e:
        return {"error": f"Failed to open mbox: {e}"}

    messages = []
    for i, msg in enumerate(mbox):
        if i >= max_messages:
            break
        messages.append(
            {
                "index": i,
                "subject": msg.get("Subject", ""),
                "from": msg.get("From", ""),
                "to": msg.get("To", ""),
                "date": msg.get("Date", ""),
                "message_id": msg.get("Message-ID", ""),
            }
        )

    return {
        "file": str(path.absolute()),
        "total_messages": len(mbox),
        "parsed_count": len(messages),
        "messages": messages,
    }
