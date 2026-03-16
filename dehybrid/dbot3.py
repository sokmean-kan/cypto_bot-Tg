import os
import base64
import logging
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from telegram import Update
from telegram.ext import (
    Application,
    MessageHandler,
    CommandHandler,
    filters,
    ContextTypes
)

# ─── Load ENV ─────────────────────────────────────────────
load_dotenv()

BOT_TOKEN       = os.getenv("TELEGRAM_BOT_TOKEN")
ALLOWED_CHAT_ID = os.getenv("ALLOWED_CHAT_ID")
PRIVATE_KEY_STR = os.getenv("RSA_PRIVATE_KEY")

# ─── Logging ──────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)

# ─── Load Private Key ─────────────────────────────────────
def load_private_key():
    key_str = PRIVATE_KEY_STR.strip()
    if "-----BEGIN" not in key_str:
        formatted = "\n".join(
            key_str[i:i+64] for i in range(0, len(key_str), 64)
        )
        key_str = f"-----BEGIN PRIVATE KEY-----\n{formatted}\n-----END PRIVATE KEY-----"
    return serialization.load_pem_private_key(
        key_str.encode(),
        password=None,
        backend=default_backend()
    )

# ─── RSA Only Decrypt ─────────────────────────────────────
def decrypt(encrypted_base64: str) -> str:
    try:
        private_key = load_private_key()
        encrypted_bytes = base64.b64decode(encrypted_base64)
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # ✅ SHA256
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode("utf-8")
    except base64.binascii.Error:
        return "❌ Invalid encrypt data format!"
    except ValueError:
        return "❌ Wrong private key or corrupted data!"
    except Exception as e:
        return f"❌ Decryption failed: {str(e)}"

# ─── Hybrid Decrypt ───────────────────────────────────────
def hybrid_decrypt(encrypted_combined: str) -> str:
    try:
        private_key = load_private_key()

        # Split by "." separator
        parts = encrypted_combined.strip().split(".")
        if len(parts) != 3:
            # Fallback to pure RSA
            return decrypt(encrypted_combined)

        encrypted_aes_key = base64.b64decode(parts[0])
        iv = base64.b64decode(parts[1])
        encrypted_data = base64.b64decode(parts[2])

        # Step 1 — Decrypt AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # ✅ SHA256
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Step 2 — Decrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Step 3 — Remove padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plain_text = unpadder.update(padded_data) + unpadder.finalize()

        return plain_text.decode("utf-8")

    except base64.binascii.Error:
        return "❌ Invalid encrypt data format!"
    except ValueError:
        return "❌ Wrong private key or corrupted data!"
    except Exception as e:
        return f"❌ Decryption failed: {str(e)}"

# ─── Check Authorization ──────────────────────────────────
def is_authorized(chat_id) -> bool:
    if ALLOWED_CHAT_ID is None:
        return True
    return str(chat_id) == ALLOWED_CHAT_ID

# ─── Handlers ─────────────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_chat.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    await update.message.reply_text(
        "👋 <b>Welcome to RSA v3 Decrypt Bot!</b>\n\n"
        "Just send or forward your encrypted text\n"
        "and I will decrypt it for you! 🔓\n\n"
        "/clear - Clear all chat messages",
        parse_mode="HTML"
    )

async def clear(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_chat.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return

    chat_id = update.effective_chat.id
    message_id = update.message.message_id
    deleted = 0

    for i in range(message_id, 0, -1):
        try:
            await context.bot.delete_message(
                chat_id=chat_id,
                message_id=i
            )
            deleted += 1
        except Exception:
            break

    await context.bot.send_message(
        chat_id=chat_id,
        text=f"🧹 Cleared <b>{deleted}</b> messages!",
        parse_mode="HTML"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_chat.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return

    encrypted_text = update.message.text.strip()
    decrypted = hybrid_decrypt(encrypted_text)

    await update.message.reply_text(
        text=f"🟢 <b>V3Result:</b>\n\n<code>{decrypted}</code>",
        parse_mode="HTML"
    )

# ─── Main ─────────────────────────────────────────────────
def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("clear", clear))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("▶ v3 Decrypt Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()