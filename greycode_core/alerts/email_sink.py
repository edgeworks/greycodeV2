from __future__ import annotations

import os
import smtplib
import base64
import hashlib
from email.message import EmailMessage
from typing import List, Optional

from cryptography.fernet import Fernet, InvalidToken

from .models import AlertEvent


def _split_csv(s: str) -> List[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def _boolish(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on", "enabled")


def _mask_indicator(ind: str) -> str:
    if not ind:
        return ""
    if len(ind) <= 20:
        return ind
    return ind[:12] + "…" + ind[-8:]


def _fernet() -> Fernet:
    secret = os.getenv("GREYCODE_SESSION_SECRET", "")
    if not secret:
        raise RuntimeError("GREYCODE_SESSION_SECRET not set (needed to decrypt SMTP password).")
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""


class EmailSink:
    def __init__(
        self,
        host: str,
        port: int,
        mail_from: str,
        rcpt_to: List[str],
        subject_prefix: str = "[Greycode]",
        username: Optional[str] = None,
        password: Optional[str] = None,
        starttls: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.mail_from = mail_from
        self.rcpt_to = rcpt_to
        self.subject_prefix = subject_prefix
        self.username = username
        self.password = password
        self.starttls = starttls

    @classmethod
    def from_cfg(cls, cfg: dict[str, str]) -> "EmailSink":
        host = (cfg.get("notify_smtp_host") or "").strip()
        port_raw = (cfg.get("notify_smtp_port") or "25").strip()
        mail_from = (cfg.get("notify_email_from") or "greycode@localhost").strip()
        rcpt_to = _split_csv((cfg.get("notify_email_to") or "").strip())
        subject_prefix = (cfg.get("notify_email_subject_prefix") or "[Greycode]").strip()

        username = (cfg.get("notify_smtp_user") or "").strip() or None
        password_enc = (cfg.get("notify_smtp_pass_enc") or "").strip()
        password = decrypt_secret(password_enc) if password_enc else None
        starttls = _boolish(cfg.get("notify_smtp_starttls"), default=False)

        try:
            port = int(port_raw)
        except Exception:
            port = 25

        if not host or not rcpt_to:
            raise RuntimeError("EmailSink misconfigured: notify_smtp_host and notify_email_to are required")

        return cls(
            host=host,
            port=port,
            mail_from=mail_from,
            rcpt_to=rcpt_to,
            subject_prefix=subject_prefix,
            username=username,
            password=password,
            starttls=starttls,
        )

    def _subject(self, alert: AlertEvent) -> str:
        indicator = alert.effective_indicator or alert.sha256 or ""
        indicator_short = _mask_indicator(indicator)

        if alert.transition:
            return f"{self.subject_prefix} {alert.alert_type} {alert.transition} {indicator_short}".strip()

        return f"{self.subject_prefix} {alert.alert_type} {alert.status} {indicator_short}".strip()

    def _body_lines(self, alert: AlertEvent) -> List[str]:
        lines: List[str] = []

        lines.append(f"Alert Type: {alert.alert_type}")
        lines.append(f"Status: {alert.status}")

        if alert.effective_indicator_type:
            lines.append(f"Indicator Type: {alert.effective_indicator_type}")
        if alert.effective_indicator:
            lines.append(f"Indicator: {alert.effective_indicator}")

        if alert.sha256:
            lines.append(f"SHA256: {alert.sha256}")

        if alert.transition:
            lines.append(f"Transition: {alert.transition}")

        if alert.listed_by:
            lines.append(f"Listed By: {', '.join(alert.listed_by)}")
        if alert.vendors_added:
            lines.append(f"Vendors Added: {', '.join(alert.vendors_added)}")
        if alert.vendors_removed:
            lines.append(f"Vendors Removed: {', '.join(alert.vendors_removed)}")

        if alert.image:
            lines.append(f"Image: {alert.image}")
        if alert.computer:
            lines.append(f"Computer: {alert.computer}")
        if alert.source:
            lines.append(f"Source: {alert.source}")

        if alert.vt_malicious or alert.vt_suspicious:
            lines.append("")
            lines.append(f"VT malicious: {alert.vt_malicious}")
            lines.append(f"VT suspicious: {alert.vt_suspicious}")

        if alert.vt_link or alert.ui_link:
            lines.append("")
        if alert.vt_link:
            lines.append(f"VirusTotal: {alert.vt_link}")
        if alert.ui_link:
            lines.append(f"Greycode UI: {alert.ui_link}")

        if alert.message:
            lines.append("")
            lines.append(alert.message)

        return lines

    async def send(self, alert: AlertEvent) -> None:
        # smtplib is blocking; acceptable for current volume.
        msg = EmailMessage()
        msg["Subject"] = self._subject(alert)
        msg["From"] = self.mail_from
        msg["To"] = ", ".join(self.rcpt_to)
        msg.set_content("\n".join(self._body_lines(alert)))

        with smtplib.SMTP(self.host, self.port, timeout=10) as s:
            if self.starttls:
                s.starttls()
            if self.username and self.password:
                s.login(self.username, self.password)
            s.send_message(msg)