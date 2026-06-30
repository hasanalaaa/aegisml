import os
from slack_bolt.async_app import AsyncApp

# For Phase 10 mock: token checking
slack_app = AsyncApp(
    token=os.environ.get("SLACK_BOT_TOKEN", "xoxb-mock"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET", "mock-secret")
)

@slack_app.command("/aegis-scan")
async def handle_scan_command(ack, respond, command):
    await ack()
    url = command.get("text", "").strip()
    if not url:
        await respond("Please provide a model URL. Usage: /aegis-scan <url>")
        return
        
    await respond({
        "response_type": "in_channel",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🛡️ AegisML Scan Requested"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Model:* {url}\n*Status:* Queued for scanning..."}
            }
        ]
    })
