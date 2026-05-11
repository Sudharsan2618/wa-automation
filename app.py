"""
TATTI WhatsApp Flow Webhook — app.py
Based strictly on Meta's documented Cloud API webhook payload structure.

Save strategy (two-phase upsert by flow_token):
  Phase 1 → /flow data_exchange (CATEGORY screen):
             upsert with status="in_progress" immediately — data is never lost
             even if the user drops off before completing the CONFIRMATION screen.
  Phase 2 → /webhook nfm_reply (CONFIRMATION complete action):
             upsert the SAME document (matched by flow_token) with degree,
             confirmed, wa_phone, wa_message_id, wa_display_name, status="completed".

Official webhook payload reference:
  entry[].id                                    → WABA ID
  entry[].changes[].field                       → always "messages"
  entry[].changes[].value.messaging_product     → "whatsapp"
  entry[].changes[].value.metadata.phone_number_id
  entry[].changes[].value.metadata.display_phone_number
  entry[].changes[].value.contacts[].wa_id      → user's WA ID
  entry[].changes[].value.contacts[].profile.name → user's display name
  entry[].changes[].value.messages[].id         → message ID (wamid...)
  entry[].changes[].value.messages[].from       → user's phone number
  entry[].changes[].value.messages[].timestamp  → unix timestamp (string)
  entry[].changes[].value.messages[].type       → "interactive" for flow replies
  entry[].changes[].value.messages[].interactive.type        → "nfm_reply"
  entry[].changes[].value.messages[].interactive.nfm_reply.name        → "flow"
  entry[].changes[].value.messages[].interactive.nfm_reply.body        → "Sent"
  entry[].changes[].value.messages[].interactive.nfm_reply.response_json → JSON string
  entry[].changes[].value.statuses[]            → delivery/read receipts (skip these)

Flow /flow endpoint decrypted request keys:
  version, action (ping|init|data_exchange), flow_token, screen, data

Flow response_json keys (TATTI complete action payload):
  full_name, email, qualification, current_status,
  preferred_batch, mode_of_study, category, degree, confirmed, flow_token
"""

from flask import Flask, request, jsonify
import os
import json
import base64
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

# ── MongoDB Setup ─────────────────────────────────────────────────────────────

mongo_client = MongoClient(MONGO_URI)
db           = mongo_client["whatsapp-automation"]
leads_col    = db["flow_leads"]

# sparse=True so in_progress docs (no wa_message_id yet) don't collide
leads_col.create_index("wa_message_id", unique=True, sparse=True)

# Non-unique index on flow_token for fast upsert lookups in both phases
leads_col.create_index("flow_token")

print("✅ Connected to MongoDB — db: whatsapp-automation, collection: flow_leads")

# ── Encryption Helpers ────────────────────────────────────────────────────────

def load_private_key():
    with open("./private_rsa.pem", "rb") as f:
        return load_pem_private_key(f.read(), password=None, backend=default_backend())

def decrypt_flow_request(encrypted_flow_data: str, encrypted_aes_key: str, initial_vector: str) -> dict:
    """
    AES-GCM + RSA-OAEP decryption for Meta Flow encrypted requests.

    Steps:
      1. RSA-OAEP-SHA256 decrypt the AES key using your private key.
      2. AES-GCM decrypt the body using that AES key and the provided IV.
      3. Last 16 bytes of encrypted_flow_data is the GCM auth tag.

    Raises Exception on failure — caller returns HTTP 421 to Meta.
    """
    private_key = load_private_key()

    aes_key = private_key.decrypt(
        base64.b64decode(encrypted_aes_key),
        OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None),
    )

    iv             = base64.b64decode(initial_vector)
    encrypted_data = base64.b64decode(encrypted_flow_data)
    encrypted_body = encrypted_data[:-16]   # everything before the last 16 bytes
    auth_tag       = encrypted_data[-16:]   # last 16 bytes = GCM auth tag

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, auth_tag),
        backend=default_backend(),
    ).decryptor()

    return json.loads((decryptor.update(encrypted_body) + decryptor.finalize()).decode("utf-8"))


def encrypt_flow_response(response_body: dict, encrypted_aes_key: str, initial_vector: str) -> str:
    """
    AES-GCM encrypt the response back to Meta.

    Meta requires:
      - Same AES key decrypted from the request.
      - IV = original IV with every bit flipped (XOR 0xFF).
      - Return value = base64( ciphertext + 16-byte GCM auth tag ).
    """
    private_key = load_private_key()

    aes_key = private_key.decrypt(
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


# ── MongoDB Helpers ───────────────────────────────────────────────────────────

def upsert_partial_lead(flow_token: str, data: dict):
    """
    Phase 1 — called from /flow when CATEGORY data_exchange fires.

    Upserts by flow_token. Sets status="in_progress".
    $setOnInsert is used for created_at so it only stamps on first insert.
    This runs BEFORE we send the routing response to Meta so the data
    is always persisted even if the user drops off mid-flow.
    """
    now = datetime.now(timezone.utc)

    try:
        result = leads_col.update_one(
            {"flow_token": flow_token},
            {
                "$set": {
                    "flow_token"      : flow_token,
                    "full_name"       : data.get("full_name"),
                    "email"           : data.get("email"),
                    "qualification"   : data.get("qualification"),
                    "current_status"  : data.get("current_status"),
                    "preferred_batch" : data.get("preferred_batch"),
                    "mode_of_study"   : data.get("mode_of_study"),
                    "category"        : data.get("category"),
                    "status"          : "in_progress",
                    "last_updated_at" : now,
                },
                "$setOnInsert": {
                    "created_at": now,
                },
            },
            upsert=True,
        )

        if result.upserted_id:
            print(f"✅ Phase 1 — new lead inserted (in_progress) → flow_token={flow_token} | name={data.get('full_name')} | category={data.get('category')}")
        else:
            print(f"✅ Phase 1 — lead updated (in_progress) → flow_token={flow_token}")

    except Exception as e:
        print(f"❌ upsert_partial_lead error: {e}")


def get_contact_name(contacts: list, wa_phone: str) -> str:
    """Match wa_id in contacts[] to get the display name."""
    for contact in contacts:
        if contact.get("wa_id") == wa_phone:
            return contact.get("profile", {}).get("name", "")
    if contacts:
        return contacts[0].get("profile", {}).get("name", "")
    return ""


def complete_lead(message: dict, contacts: list, metadata: dict, flow_data: dict, raw_webhook: dict):
    """
    Phase 2 — called from /webhook when CONFIRMATION complete action fires.

    Upserts by flow_token — updates the Phase 1 document with the
    remaining fields and sets status="completed".
    If Phase 1 document is missing (edge case), inserts a full document.
    """
    wa_phone   = message.get("from", "")
    flow_token = flow_data.get("flow_token", "")
    now        = datetime.now(timezone.utc)

    update_fields = {
        # ── WhatsApp identity (only available from webhook) ───────────────
        "wa_message_id"    : message.get("id"),
        "wa_phone"         : wa_phone,
        "wa_display_name"  : get_contact_name(contacts, wa_phone),
        "phone_number_id"  : metadata.get("phone_number_id"),
        "message_timestamp": message.get("timestamp"),

        # ── Fields only available after CONFIRMATION screen ───────────────
        "degree"           : flow_data.get("degree"),
        "confirmed"        : flow_data.get("confirmed"),

        # ── Re-set all earlier fields (covers case where Phase 1 was skipped)
        "flow_token"       : flow_token,
        "full_name"        : flow_data.get("full_name"),
        "email"            : flow_data.get("email"),
        "qualification"    : flow_data.get("qualification"),
        "current_status"   : flow_data.get("current_status"),
        "preferred_batch"  : flow_data.get("preferred_batch"),
        "mode_of_study"    : flow_data.get("mode_of_study"),
        "category"         : flow_data.get("category"),

        # ── Status + timestamps ───────────────────────────────────────────
        "status"           : "completed",
        "received_at"      : now,
        "last_updated_at"  : now,

        # ── Raw audit trail ───────────────────────────────────────────────
        "raw_flow_payload" : flow_data,
        "raw_webhook"      : raw_webhook,
    }

    # Match on flow_token if present; fall back to wa_message_id
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
            print(f"✅ Phase 2 — new completed lead inserted → name={flow_data.get('full_name')} | phone={wa_phone} | degree={flow_data.get('degree')} | confirmed={flow_data.get('confirmed')}")
        else:
            print(f"✅ Phase 2 — existing lead completed → flow_token={flow_token} | degree={flow_data.get('degree')} | confirmed={flow_data.get('confirmed')}")

    except DuplicateKeyError:
        print(f"⚠️  Duplicate ignored — wa_message_id already stored: {message.get('id')}")
    except Exception as e:
        print(f"❌ complete_lead error: {e}")


# ── Flow Endpoint ─────────────────────────────────────────────────────────────

@app.route("/flow", methods=["POST"])
def flow_endpoint():
    """
    WhatsApp Flow Endpoint — called by Meta mid-flow for data_exchange.

    Register in Meta: Flow Builder → your flow → Endpoint URL → <your-domain>/flow

    Handles:
      ping          → Meta health check (save URL in Flow Builder)
      init          → Flow opened by user (WELCOME is static, return empty data)
      data_exchange → Footer tapped on CATEGORY screen

    On data_exchange:
      1. Saves partial lead to MongoDB (Phase 1) BEFORE responding.
      2. Returns routing response to Meta.

    Routing:
      category == "degree"  → DEGREE_SELECTION
      category == anything else → CONFIRMATION (degree fields not needed)

    Flow JSON routing_model must be:
      "CATEGORY": ["DEGREE_SELECTION", "CONFIRMATION"]

    HTTP 421 returned when decryption fails (Meta's expected error code).
    """
    raw_body = request.get_json(silent=True) or {}

    print("=" * 60)
    print("📥 FLOW ENDPOINT POST received")

    # ── Detect encrypted vs unencrypted mode ─────────────────────────────────
    is_encrypted = "encrypted_flow_data" in raw_body

    if is_encrypted:
        print("🔐 Encrypted request detected — decrypting...")
        try:
            body        = decrypt_flow_request(
                raw_body["encrypted_flow_data"],
                raw_body["encrypted_aes_key"],
                raw_body["initial_vector"],
            )
            aes_key_b64 = raw_body["encrypted_aes_key"]
            iv_b64      = raw_body["initial_vector"]
            print("🔓 Decrypted request body:")
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
    action     = body.get("action", "")
    screen     = body.get("screen", "")
    flow_token = body.get("flow_token", "")
    data       = body.get("data", {})

    def send_response(response_dict: dict):
        if is_encrypted:
            encrypted = encrypt_flow_response(response_dict, aes_key_b64, iv_b64)
            return app.response_class(response=encrypted, status=200, mimetype="text/plain")
        return jsonify(response_dict), 200

    # ── 1. Ping ───────────────────────────────────────────────────────────────
    if action == "ping":
        print("🏓 Ping received — responding active")
        return send_response({"version": version, "data": {"status": "active"}})

    # ── 2. Init ───────────────────────────────────────────────────────────────
    if action == "init":
        print("🚀 Init received — WELCOME is static, returning empty data")
        return send_response({"version": version, "data": {}})

    # ── 3. data_exchange — CATEGORY screen ───────────────────────────────────
    if action == "data_exchange" and screen == "CATEGORY":
        category = data.get("category", "")

        print(
            f"🔄 CATEGORY data_exchange — "
            f"category={category} | name={data.get('full_name')} | email={data.get('email')}"
        )

        # ── PHASE 1: Save to MongoDB BEFORE responding to Meta ────────────
        upsert_partial_lead(flow_token, data)

        forwarded_data = {
            "full_name"       : data.get("full_name"),
            "email"           : data.get("email"),
            "qualification"   : data.get("qualification"),
            "current_status"  : data.get("current_status"),
            "preferred_batch" : data.get("preferred_batch"),
            "mode_of_study"   : data.get("mode_of_study"),
            "category"        : category,
        }

        if category == "degree":
            print("➡️  Routing → DEGREE_SELECTION")
            return send_response({
                "version": version,
                "screen" : "DEGREE_SELECTION",
                "data"   : forwarded_data,
            })
        else:
            print(f"➡️  Non-degree '{category}' — routing → CONFIRMATION")
            return send_response({
                "version": version,
                "screen" : "CONFIRMATION",
                "data"   : {**forwarded_data, "degree": ""},
            })

    # ── Fallback ──────────────────────────────────────────────────────────────
    print(f"⚠️  Unhandled — action='{action}' | screen='{screen}'")
    return send_response({
        "version": version,
        "data"   : {"error": f"unhandled action '{action}' on screen '{screen}'"},
    })


# ── Webhook Routes ────────────────────────────────────────────────────────────

@app.route("/webhook", methods=["GET"])
def verify():
    """Meta GET to verify webhook. Must echo hub.challenge with 200."""
    mode      = request.args.get("hub.mode")
    token     = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("✅ Webhook verified by Meta")
        return challenge, 200

    print(f"❌ Webhook verification failed — mode={mode} token={token}")
    return "Forbidden", 403


@app.route("/webhook", methods=["POST"])
def webhook_listener():
    """
    Receives all WhatsApp Cloud API webhook events.

    For TATTI flows this fires when the user hits Submit on CONFIRMATION
    (the "complete" action). Full payload is in:
      messages[].interactive.nfm_reply.response_json  (a JSON string)

    This is Phase 2 of the save strategy — upserts the in_progress
    document (created in Phase 1) with the final fields + status="completed".
    """
    raw_webhook = request.get_json(silent=True) or {}

    print("=" * 60)
    print("📥 WEBHOOK POST received:")
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

                # Skip delivery/read receipts
                if statuses and not messages:
                    for s in statuses:
                        print(f"   ↳ status: id={s.get('id')} status={s.get('status')} recipient={s.get('recipient_id')}")
                    print("⏭️  Skipping — status update, not a message")
                    continue

                for message in messages:
                    msg_id   = message.get("id")
                    msg_from = message.get("from")
                    msg_type = message.get("type")
                    msg_ts   = message.get("timestamp")

                    print(f"📨 message: id={msg_id} | from={msg_from} | type={msg_type} | timestamp={msg_ts}")

                    if msg_type != "interactive":
                        print(f"⏭️  Skipping — type '{msg_type}' is not 'interactive'")
                        continue

                    interactive      = message.get("interactive", {})
                    interactive_type = interactive.get("type")
                    print(f"🔗 interactive.type = {interactive_type}")

                    if interactive_type != "nfm_reply":
                        print(f"⏭️  Skipping — interactive.type '{interactive_type}' is not 'nfm_reply'")
                        continue

                    nfm_reply         = interactive.get("nfm_reply", {})
                    nfm_name          = nfm_reply.get("name")
                    nfm_body          = nfm_reply.get("body")
                    response_json_str = nfm_reply.get("response_json", "{}")

                    print(f"📋 nfm_reply.name={nfm_name} | body={nfm_body}")
                    print(f"📋 response_json (raw): {response_json_str}")

                    try:
                        flow_data = json.loads(response_json_str)
                        print(f"✅ Parsed flow_data keys: {list(flow_data.keys())}")
                    except json.JSONDecodeError as e:
                        print(f"❌ Failed to parse response_json: {e}")
                        continue

                    # ── PHASE 2: Complete the lead ────────────────────────
                    complete_lead(message, contacts, metadata, flow_data, raw_webhook)

    except Exception as e:
        print(f"❌ Webhook processing error: {e}")

    # Always return 200 — Meta retries on anything else
    return jsonify({"status": "ok"}), 200


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(port=5000, debug=True)