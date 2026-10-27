import asyncio

from iknowurhere.database import Alert
import iknowurhere.notifications as notifications


def test_notifications_are_disabled_without_explicit_configuration(monkeypatch):
    monkeypatch.delenv("IKNOWURHERE_DISCORD_WEBHOOK", raising=False)
    monkeypatch.delenv("IKNOWURHERE_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("IKNOWURHERE_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setattr(notifications, "_post_json", lambda *args: (_ for _ in ()).throw(AssertionError()))
    asyncio.run(notifications.notify_alerts([
        Alert("new_device", "A new host appeared", 0.8, "192.168.8.7", None, None, "now")
    ]))


def test_webhook_dispatch_sends_concise_alert_without_mac(monkeypatch):
    captured = []

    async def immediate_thread_call(function, *args):
        return function(*args)

    monkeypatch.setattr(notifications.asyncio, "to_thread", immediate_thread_call)
    monkeypatch.setenv("IKNOWURHERE_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/fake/fake")
    monkeypatch.delenv("IKNOWURHERE_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("IKNOWURHERE_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setattr(notifications, "_send_discord", lambda url, message: captured.append((url, message)))
    alert = Alert("gateway_mac_changed", "Gateway identity changed", 0.98,
                  "192.168.8.1", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:99", "now")
    asyncio.run(notifications.notify_alerts([alert]))
    assert captured[0][0].startswith("https://discord.com/")
    assert "192.168.8.1" in captured[0][1]
    assert "aa:bb" not in captured[0][1]
