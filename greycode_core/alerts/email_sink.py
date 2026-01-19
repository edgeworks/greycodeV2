from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import List, Optional

from .models import AlertEvent


def _split_csv(s: str) -> List[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


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
    def from_env(cls) -> "EmailSink":
        host = os.getenv("ALERT_SMTP_HOST", "").strip()
        port = int(os.getenv("ALERT_SMTP_PORT", "25").strip())
        mail_from = os.getenv("ALERT_EMAIL_FROM", "greycode@localhost").strip()
        rcpt_to = _split_csv(os.getenv("ALERT_EMAIL_TO", "").strip())
        subject_prefix = os.getenv("ALERT_EMAIL_SUBJECT_PREFIX", "[Greycode]").strip()

        username = os.getenv("ALERT_SMTP_USER", "").strip() or None
        password = os.getenv("ALERT_SMTP_PASS", "").strip() or None
        starttls = os.getenv("ALERT_SMTP_STARTTLS", "0").strip() == "1"

        if not host or not rcpt_to:
            raise RuntimeError("EmailSink misconfigured: ALERT_SMTP_HOST and ALERT_EMAIL_TO are required")

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

    async def send(self, alert: AlertEvent) -> None:
        # Note: smtplib is blocking; for your current volumes this is fine.
        # If you later need high throughput, run sending in a thread pool.
        msg = EmailMessage()

        subj = f"{self.subject_prefix} {alert.alert_type} {alert.status} {alert.sha256[:12]}..."
        msg["Subject"] = subj
        msg["From"] = self.mail_from
        msg["To"] = ", ".join(self.rcpt_to)

        lines = []
        lines.append(f"Alert Type: {alert.alert_type}")
        lines.append(f"Status: {alert.status}")
        lines.append(f"SHA256: {alert.sha256}")
        lines.append("")
        if alert.image:
            lines.append(f"Image: {alert.image}")
        if alert.computer:
            lines.append(f"Computer: {alert.computer}")
        if alert.source:
            lines.append(f"Source: {alert.source}")
        lines.append("")
        lines.append(f"VT malicious: {alert.vt_malicious}")
        lines.append(f"VT suspicious: {alert.vt_suspicious}")
        if alert.vt_link:
            lines.append(f"VirusTotal: {alert.vt_link}")
        if alert.ui_link:
            lines.append(f"Greycode UI: {alert.ui_link}")
        if alert.message:
            lines.append("")
            lines.append(alert.message)

        msg.set_content("\n".join(lines))

        with smtplib.SMTP(self.host, self.port, timeout=10) as s:
            if self.starttls:
                s.starttls()
            if self.username and self.password:
                s.login(self.username, self.password)
            s.send_message(msg)
