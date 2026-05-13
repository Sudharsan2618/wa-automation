from flask import Flask, request, jsonify
import os
import json
import base64
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

load_dotenv()

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

ACCESS_TOKEN           = os.getenv("ACCESS_TOKEN")
PHONE_NUMBER_ID        = os.getenv("PHONE_NUMBER_ID")
VERIFY_TOKEN           = "Sunflower@2618"
MONGO_URI              = os.getenv("MONGO_URI")
PRIVATE_KEY_PASSPHRASE = os.getenv("PRIVATE_KEY_PASSPHRASE", "")

# ── Prospectus Config ─────────────────────────────────────────────────────────
# Path to your local PDF (used for one-time upload on startup).
# If you already have a permanent media_id (uploaded previously),
# set PROSPECTUS_MEDIA_ID in your .env to skip the re-upload on every restart.
# PROSPECTUS_PDF_PATH = os.getenv("PROSPECTUS_PDF_PATH", "./prospectus.pdf")
PROSPECTUS_MEDIA_ID = os.getenv("PROSPECTUS_MEDIA_ID", "1981955689074811")   # pre-set to avoid re-upload

PROSPECTUS_MESSAGE = (
    "Hi 👋\n\n"
    "📚 We are pleased to share the course prospectus for our 2026 Future-Ready Degree Programs:\n\n"
    "🎓 B.Com FinTech & AI\n"
    "🎬 B.Sc Film & TV Production\n"
    "🌱 B.Sc Renewable Energy\n\n"
    "Please find the attached prospectus for complete details on courses, curriculum, "
    "career opportunities and fee structure.\n\n"
    "📍 Our Locations:\n"
    "PERIYAR MANIAMMAI INSTITUTE OF SCIENCE & TECHNOLOGY (PMIST)\n"
    "Periyar Nagar, Vallam, Thanjavur - 613403\n"
    "PH: 9884170589 / 7598443587"
)

# ── MongoDB Setup ─────────────────────────────────────────────────────────────

mongo_client = MongoClient(MONGO_URI)
db           = mongo_client["whatsapp-automation"]
leads_col    = db["flow_leads"]

leads_col.create_index("wa_message_id", unique=True, sparse=True)
leads_col.create_index("flow_token")

print("✅ MongoDB connected — whatsapp-automation.flow_leads")

# ── RSA / AES Encryption Helpers ─────────────────────────────────────────────

def load_private_key():
    with open("./private_rsa.pem", "rb") as f:
        return load_pem_private_key(f.read(), password=None, backend=default_backend())


def decrypt_flow_request(encrypted_flow_data, encrypted_aes_key, initial_vector):
    pk = load_private_key()
    aes_key = pk.decrypt(
        base64.b64decode(encrypted_aes_key),
        OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None),
    )
    iv             = base64.b64decode(initial_vector)
    raw            = base64.b64decode(encrypted_flow_data)
    encrypted_body = raw[:-16]
    auth_tag       = raw[-16:]
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, auth_tag),
        backend=default_backend(),
    ).decryptor()
    plaintext = decryptor.update(encrypted_body) + decryptor.finalize()
    return json.loads(plaintext.decode("utf-8"))


def encrypt_flow_response(response_body, encrypted_aes_key, initial_vector):
    pk = load_private_key()
    aes_key = pk.decrypt(
        base64.b64decode(encrypted_aes_key),
        OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None),
    )
    iv         = base64.b64decode(initial_vector)
    flipped_iv = bytes(b ^ 0xFF for b in iv)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(flipped_iv),
        backend=default_backend(),
    ).encryptor()
    body_bytes = json.dumps(response_body).encode("utf-8")
    ciphertext = encryptor.update(body_bytes) + encryptor.finalize()
    return base64.b64encode(ciphertext + encryptor.tag).decode("utf-8")




def send_prospectus(wa_phone: str, media_id: str):
    """
    Send the prospectus PDF to wa_phone inside the 24-hour customer
    service window that was opened when the user submitted the Flow.

    Uses a document message with a caption so both the text and the
    PDF arrive in a single bubble — no template required.

    NOTE: WhatsApp captions on documents are plain text only;
    emoji and newlines work but markdown (*bold* etc.) does not render.
    """
    url = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type"   : "individual",
        "to"               : wa_phone,
        "type"             : "document",
        "document"         : {
            "id"      : media_id,
            "caption" : PROSPECTUS_MESSAGE,
            "filename": "TATTI_PMIST_Prospectus_2026.pdf",
        },
    }
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {ACCESS_TOKEN}",
            "Content-Type" : "application/json",
        },
        json=payload,
    )
    result = resp.json()
    if resp.status_code == 200 and "messages" in result:
        print(f"✅ Prospectus sent to {wa_phone} | msg_id={result['messages'][0]['id']}")
    else:
        print(f"❌ Prospectus send failed for {wa_phone}: {result}")


# ── One-time startup: ensure we have a media_id ───────────────────────────────

def init_prospectus_media_id() -> str:
    """
    Returns a usable media_id for the prospectus PDF.

    Priority:
      1. PROSPECTUS_MEDIA_ID env var (already uploaded previously) — fastest path.
      2. Upload from PROSPECTUS_PDF_PATH and return the new id.
    """
    if PROSPECTUS_MEDIA_ID:
        print(f"✅ Using cached PROSPECTUS_MEDIA_ID={PROSPECTUS_MEDIA_ID}")
        return PROSPECTUS_MEDIA_ID

    # if not os.path.exists(PROSPECTUS_PDF_PATH):
    #     print(
    #         f"⚠️  PROSPECTUS_PDF_PATH '{PROSPECTUS_PDF_PATH}' not found. "
    #         "Prospectus sending will be disabled."
    #     )
    #     return ""

    # try:
    #     return upload_prospectus_pdf(PROSPECTUS_PDF_PATH)
    # except Exception as e:
    #     print(f"❌ Could not upload prospectus PDF at startup: {e}")
    #     return ""


# Resolve at startup so every webhook call can use this immediately.
_PROSPECTUS_MEDIA_ID: str = init_prospectus_media_id()


# ── MongoDB Save Helpers ──────────────────────────────────────────────────────

def upsert_lead_from_flow(flow_token: str, data: dict):
    now = datetime.now(timezone.utc)
    try:
        result = leads_col.update_one(
            {"flow_token": flow_token},
            {
                "$set": {
                            "flow_token"      : flow_token,
                            "full_name"       : data.get("full_name"),
                            "email"           : data.get("email"),
                            "city"            : data.get("city"),          # ← add this
                            "qualification"   : data.get("qualification"),
                            "current_status"  : data.get("current_status"),
                            "degree"          : data.get("degree"),
                            "status"          : "in_progress",
                            "last_updated_at" : now,
                        },
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )
        action = "inserted" if result.upserted_id else "updated"
        print(
            f"✅ Phase 1 ({action}) → "
            f"flow_token={flow_token} | "
            f"name={data.get('full_name')} | "
            f"degree={data.get('degree')}"
        )
    except Exception as e:
        print(f"❌ upsert_lead_from_flow error: {e}")


def get_contact_name(contacts: list, wa_phone: str) -> str:
    for c in contacts:
        if c.get("wa_id") == wa_phone:
            return c.get("profile", {}).get("name", "")
    return contacts[0].get("profile", {}).get("name", "") if contacts else ""


def complete_lead_from_webhook(message, contacts, metadata, flow_data, raw_webhook):
    wa_phone   = message.get("from", "")
    flow_token = flow_data.get("flow_token", "")
    now        = datetime.now(timezone.utc)

    update_fields = {
    "wa_message_id"    : message.get("id"),
    "wa_phone"         : wa_phone,
    "wa_display_name"  : get_contact_name(contacts, wa_phone),
    "phone_number_id"  : metadata.get("phone_number_id"),
    "message_timestamp": message.get("timestamp"),
    "confirmed"        : flow_data.get("confirmed"),
    "flow_token"       : flow_token,
    "full_name"        : flow_data.get("full_name"),
    "email"            : flow_data.get("email"),
    "city"             : flow_data.get("city"),        # ← add this
    "qualification"    : flow_data.get("qualification"),
    "current_status"   : flow_data.get("current_status"),
    "degree"           : flow_data.get("degree"),
    "status"           : "completed",
    "received_at"      : now,
    "last_updated_at"  : now,
    "raw_flow_payload" : flow_data,
    "raw_webhook"      : raw_webhook,
    }

    match_key = {"flow_token": flow_token} if flow_token else {"wa_message_id": message.get("id")}

    try:
        result = leads_col.update_one(
            match_key,
            {
                "$set"        : update_fields,
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )
        if result.upserted_id:
            print(
                f"✅ Phase 2 (new doc) → "
                f"name={flow_data.get('full_name')} | "
                f"phone={wa_phone} | "
                f"confirmed={flow_data.get('confirmed')}"
            )
        else:
            print(f"✅ Phase 2 (updated) → flow_token={flow_token} | confirmed={flow_data.get('confirmed')}")

    except DuplicateKeyError:
        print(f"⚠️  Duplicate — wa_message_id already stored: {message.get('id')}")
        return   # ← already processed; skip prospectus re-send

    except Exception as e:
        print(f"❌ complete_lead_from_webhook error: {e}")
        return   # ← don't send prospectus if save failed

    # ── Send prospectus PDF inside the 24-hour window ─────────────────────────
    # The user just submitted the Flow which opens (or refreshes) the
    # 24-hour customer service window.  We send immediately — no template needed.
    if wa_phone and _PROSPECTUS_MEDIA_ID:
        send_prospectus(wa_phone, _PROSPECTUS_MEDIA_ID)
    else:
        if not wa_phone:
            print("⚠️  No wa_phone — cannot send prospectus.")
        if not _PROSPECTUS_MEDIA_ID:
            print("⚠️  No PROSPECTUS_MEDIA_ID — prospectus not sent. Check startup logs.")


# ── /flow Endpoint ────────────────────────────────────────────────────────────

@app.route("/flow", methods=["POST"])
def flow_endpoint():
    raw_body = request.get_json(silent=True) or {}

    print("=" * 60)
    print("📥 /flow POST received")

    is_encrypted = "encrypted_flow_data" in raw_body

    if is_encrypted:
        print("🔐 Encrypted — decrypting...")
        try:
            body        = decrypt_flow_request(
                raw_body["encrypted_flow_data"],
                raw_body["encrypted_aes_key"],
                raw_body["initial_vector"],
            )
            aes_key_b64 = raw_body["encrypted_aes_key"]
            iv_b64      = raw_body["initial_vector"]
            print("🔓 Decrypted body:")
            print(json.dumps(body, indent=2))
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            return "", 421
    else:
        body        = raw_body
        aes_key_b64 = None
        iv_b64      = None
        print("🔓 Unencrypted (dev mode):")
        print(json.dumps(body, indent=2))

    print("=" * 60)

    version    = body.get("version", "3.0")
    action     = body.get("action", "").lower()
    screen     = body.get("screen", "")
    flow_token = body.get("flow_token", "")
    data       = body.get("data", {})

    def send_response(payload: dict):
        if is_encrypted:
            encrypted = encrypt_flow_response(payload, aes_key_b64, iv_b64)
            return app.response_class(response=encrypted, status=200, mimetype="text/plain")
        return jsonify(payload), 200

    if action == "ping":
        print("🏓 Ping — responding active")
        return send_response({"version": version, "data": {"status": "active"}})

    if action == "init":
        print("🚀 Init — WELCOME is static, returning {}")
        return send_response({"version": version, "data": {}})

    if action == "data_exchange" and screen == "COURSE_DETAILS":
        print(
            f"🔄 COURSE_DETAILS data_exchange — "
            f"name={data.get('full_name')} | "
            f"email={data.get('email')} | "
            f"degree={data.get('degree')}"
        )
        upsert_lead_from_flow(flow_token, data)
        return send_response({
            "version": version,
            "screen" : "CONFIRMATION",
            "data"   : {
                "full_name"      : data.get("full_name"),
                "email"          : data.get("email"),
                "qualification"  : data.get("qualification"),
                "current_status" : data.get("current_status"),
                "degree"         : data.get("degree"),
            },
        })

    print(f"⚠️  Unhandled — action='{action}' | screen='{screen}'")
    return send_response({
        "version": version,
        "data"   : {"error": f"unhandled action='{action}' screen='{screen}'"},
    })


# ── /webhook Endpoint — verification ─────────────────────────────────────────

@app.route("/webhook", methods=["GET"])
def verify():
    mode      = request.args.get("hub.mode")
    token     = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("✅ Webhook verified")
        return challenge, 200
    print(f"❌ Webhook verify failed — mode={mode} token={token}")
    return "Forbidden", 403


# ── /webhook Endpoint — message events ───────────────────────────────────────

@app.route("/webhook", methods=["POST"])
def webhook_listener():
    raw_webhook = request.get_json(silent=True) or {}

    print("=" * 60)
    print("📥 /webhook POST received:")
    print(json.dumps(raw_webhook, indent=2))
    print("=" * 60)

    try:
        for entry in raw_webhook.get("entry", []):
            waba_id = entry.get("id")
            for change in entry.get("changes", []):
                field    = change.get("field")
                value    = change.get("value", {})
                metadata = value.get("metadata", {})
                contacts = value.get("contacts", [])
                messages = value.get("messages", [])
                statuses = value.get("statuses", [])

                print(
                    f"🔍 WABA={waba_id} | field={field} | "
                    f"messages={len(messages)} | statuses={len(statuses)}"
                )

                if statuses and not messages:
                    for s in statuses:
                        print(
                            f"   ↳ status: id={s.get('id')} "
                            f"status={s.get('status')} "
                            f"recipient={s.get('recipient_id')}"
                        )
                    print("⏭️  Status update — skipping")
                    continue

                for message in messages:
                    msg_id   = message.get("id")
                    msg_from = message.get("from")
                    msg_type = message.get("type")
                    msg_ts   = message.get("timestamp")

                    print(f"📨 id={msg_id} | from={msg_from} | type={msg_type} | ts={msg_ts}")

                    if msg_type != "interactive":
                        print(f"⏭️  type='{msg_type}' — not interactive, skipping")
                        continue

                    interactive      = message.get("interactive", {})
                    interactive_type = interactive.get("type")
                    print(f"🔗 interactive.type={interactive_type}")

                    if interactive_type != "nfm_reply":
                        print(f"⏭️  interactive.type='{interactive_type}' — not nfm_reply, skipping")
                        continue

                    nfm_reply         = interactive.get("nfm_reply", {})
                    response_json_str = nfm_reply.get("response_json", "{}")

                    print(f"📋 nfm_reply.name={nfm_reply.get('name')} | body={nfm_reply.get('body')}")
                    print(f"📋 response_json raw: {response_json_str}")

                    try:
                        flow_data = json.loads(response_json_str)
                        print(f"✅ flow_data keys: {list(flow_data.keys())}")
                    except json.JSONDecodeError as e:
                        print(f"❌ JSON parse error: {e}")
                        continue

                    # Phase 2 save + prospectus send (inside complete_lead_from_webhook)
                    complete_lead_from_webhook(
                        message, contacts, metadata, flow_data, raw_webhook
                    )

    except Exception as e:
        print(f"❌ Webhook processing error: {e}")

    return jsonify({"status": "ok"}), 200


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(port=5000, debug=True)