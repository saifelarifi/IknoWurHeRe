"""Optional outbound alert notifications; disabled unless explicitly configured."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .database import Alert

logger = logging.getLogger("iknowurhere.notifications")


def _post_json(url: str, payload: dict) -> None:
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "IknoWurHeRe/0.2"},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        if not 200 <= response.status < 300:
            raise URLError(f"notification endpoint returned HTTP {response.status}")


def _send_discord(webhook: str, message: str) -> None:
    if not webhook.startswith(("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/")):
        logger.error("Discord webhook ignored: expected an official HTTPS Discord webhook URL")
        return
    _post_json(webhook, {"content": message[:1900], "allowed_mentions": {"parse": []}})


def _send_telegram(token: str, chat_id: str, message: str) -> None:
    if not token or not chat_id or any(char in token for char in "/?#"):
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urlencode({"chat_id": chat_id, "text": message[:3800]}).encode("utf-8")
    request = Request(url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with urlopen(request, timeout=5) as response:
        if not 200 <= response.status < 300:
            raise URLError(f"Telegram endpoint returned HTTP {response.status}")


def _message(alert: Alert) -> str:
    # Keep notifications useful while avoiding MAC addresses and other inventory details.
    return (
        f"IknoWurHeRe alert: {alert.event_type}\n"
        f"Address: {alert.ip or 'network'}\n"
        f"Confidence: {alert.confidence:.0%}\n"
        f"Reason: {alert.reason[:700]}\n"
        f"Observed: {alert.observed_at}"
    )


async def notify_alerts(alerts: list[Alert]) -> None:
    """Send concise alerts to explicitly configured Discord/Telegram endpoints."""
    discord_webhook = os.getenv("IKNOWURHERE_DISCORD_WEBHOOK", "").strip()
    telegram_token = os.getenv("IKNOWURHERE_TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat_id = os.getenv("IKNOWURHERE_TELEGRAM_CHAT_ID", "").strip()
    if not alerts or not (discord_webhook or (telegram_token and telegram_chat_id)):
        return

    async def send_one(alert: Alert) -> None:
        message = _message(alert)
        jobs = []
        if discord_webhook:
            jobs.append(asyncio.to_thread(_send_discord, discord_webhook, message))
        if telegram_token and telegram_chat_id:
            jobs.append(asyncio.to_thread(_send_telegram, telegram_token, telegram_chat_id, message))
        for job in jobs:
            try:
                await job
            except Exception as exc:
                # Do not include configured webhook URLs or bot tokens in logs.
                logger.warning("Alert notification delivery failed (%s)", type(exc).__name__)

    await asyncio.gather(*(send_one(alert) for alert in alerts))
