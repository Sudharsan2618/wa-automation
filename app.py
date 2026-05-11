"""
TATTI WhatsApp Flow Webhook — app.py
Based strictly on Meta's documented Cloud API webhook payload structure.

Official payload reference:
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
  entry[].changes[].value.messages[].interactive.nfm_reply.response_json → JSON string of flow payload
  entry[].changes[].value.statuses[]            → delivery/read receipts (NOT messages, skip these)

Flow response_json keys (from TATTI Flow JSON complete action payload):
  full_name, email, qualification, current_status,
  preferred_batch, mode_of_study, category, degree, confirmed
  flow_token is also always included by Meta automatically.

Flow Endpoint (/flow) — data_exchange action reference:
  Request body (decrypted):
    version    → "3.0"
    action     → "ping" | "init" | "data_exchange"
    flow_token → unique token for this flow session
    screen     → current screen ID (present on data_exchange)
    data       → payload sent from the screen's on-click-action (present on data_exchange)

  Response body (for data_exchange):
    version    → echo back "3.0"
    screen     → next screen ID to navigate to
    data       → data object required by the next screen's `data` field declarations

  NOTE: In production Meta encrypts the /flow request body using your RSA public key.
        This file handles BOTH encrypted (production) and unencrypted (dev/testing) modes.
        Encryption is auto-detected based on whether "encrypted_flow_data" is present.
        To enable unencrypted mode in Meta:
          Flow Builder → your flow → Settings → toggle off "Endpoint Encryption"
"""

from flask import Flask, request, jsonify
import os
import json
import base64
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# ── Cryptography imports (required for encrypted mode) ────────────────────────
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
PRIVATE_KEY_PATH       = os.getenv("PRIVATE_KEY_PATH", "./private.pem")
PRIVATE_KEY_PASSPHRASE = os.getenv("PRIVATE_KEY_PASSPHRASE", "")
PRIVATE_KEY_CONTENT    = os.getenv("PRIVATE_KEY_CONTENT")  # optional (production)

# ── MongoDB Setup ─────────────────────────────────────────────────────────────

mongo_client = MongoClient(MONGO_URI)
db           = mongo_client["whatsapp-automation"]
leads_col    = db["flow_leads"]

# Unique index on wa_message_id — prevents duplicate inserts on Meta retries
leads_col.create_index("wa_message_id", unique=True, sparse=True)

print("✅ Connected to MongoDB — db: whatsapp-automation, collection: flow_leads")

# ── Encryption Helpers ────────────────────────────────────────────────────────

def load_private_key():
    passphrase = PRIVATE_KEY_PASSPHRASE.encode() if PRIVATE_KEY_PASSPHRASE else None

    if PRIVATE_KEY_CONTENT:
        # Load from env var (Render/production)
        return load_pem_private_key(
            PRIVATE_KEY_CONTENT.encode(),
            password=passphrase,
            backend=default_backend()
        )
    else:
        # Fallback: load from file (local dev only)
        with open("./private.pem", "rb") as f:
            return load_pem_private_key(
                f.read(),
                password=passphrase,
                backend=default_backend()
            )


def decrypt_flow_request(encrypted_flow_data: str, encrypted_aes_key: str, initial_vector: str) -> dict:
    """
    Meta's Flow encryption scheme (AES-GCM + RSA-OAEP):

      1. WhatsApp client generates a random AES-128-GCM key.
      2. That AES key is RSA-OAEP encrypted with YOUR business public key → encrypted_aes_key.
      3. The actual JSON request body is AES-GCM encrypted → encrypted_flow_data.
      4. You decrypt the AES key with your RSA private key, then decrypt the body.

    Args:
        encrypted_flow_data : base64-encoded AES-GCM ciphertext (body + 16-byte auth tag)
        encrypted_aes_key   : base64-encoded RSA-OAEP encrypted AES key
        initial_vector      : base64-encoded 12-byte GCM nonce/IV

    Returns:
        Decrypted request body as a Python dict.

    Raises:
        Exception if decryption fails — caller should return HTTP 421.
    """
    private_key = load_private_key()

    # Step 1: RSA-OAEP decrypt the AES key
    aes_key = private_key.decrypt(
        base64.b64decode(encrypted_aes_key),
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    # Step 2: Decode IV and ciphertext
    iv             = base64.b64decode(initial_vector)
    encrypted_data = base64.b64decode(encrypted_flow_data)

    # Step 3: Split ciphertext and GCM auth tag (last 16 bytes)
    encrypted_body = encrypted_data[:-16]
    auth_tag       = encrypted_data[-16:]

    # Step 4: AES-GCM decrypt
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, auth_tag),
        backend=default_backend()
    ).decryptor()

    decrypted_bytes = decryptor.update(encrypted_body) + decryptor.finalize()
    return json.loads(decrypted_bytes.decode("utf-8"))


def encrypt_flow_response(response_body: dict, encrypted_aes_key: str, initial_vector: str) -> str:
    """
    Encrypt the response back to Meta using the SAME AES key but a BIT-FLIPPED IV.

    Meta's spec requires:
      - Same AES key that was used to decrypt the request.
      - IV = each byte of the original IV XOR 0xFF (all bits flipped).
      - Response = base64( AES-GCM-ciphertext + 16-byte-auth-tag )

    Args:
        response_body       : Python dict to send back to Meta.
        encrypted_aes_key   : base64 AES key from the original request (still RSA-encrypted).
        initial_vector      : base64 IV from the original request.

    Returns:
        base64-encoded encrypted response string (plain text MIME type).
    """
    private_key = load_private_key()

    # Decrypt the AES key again (same as in decrypt_flow_request)
    aes_key = private_key.decrypt(
        base64.b64decode(encrypted_aes_key),
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    # Flip every bit of the IV
    iv         = base64.b64decode(initial_vector)
    flipped_iv = bytes(b ^ 0xFF for b in iv)

    # AES-GCM encrypt
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(flipped_iv),
        backend=default_backend()
    ).encryptor()

    body_bytes     = json.dumps(response_body).encode("utf-8")
    ciphertext     = encryptor.update(body_bytes) + encryptor.finalize()
    auth_tag       = encryptor.tag

    return base64.b64encode(ciphertext + auth_tag).decode("utf-8")


# ── Webhook Helpers ───────────────────────────────────────────────────────────

def get_contact_name(contacts: list, wa_phone: str) -> str:
    """
    Per Meta docs, value.contacts[] maps wa_id → profile.name.
    Match on wa_id == wa_phone (they're the same in Cloud API).
    """
    for contact in contacts:
        if contact.get("wa_id") == wa_phone:
            return contact.get("profile", {}).get("name", "")
    # fallback: just return first contact's name if present
    if contacts:
        return contacts[0].get("profile", {}).get("name", "")
    return ""


def save_lead(
    message: dict,
    contacts: list,
    metadata: dict,
    flow_data: dict,
    raw_webhook: dict,
):
    """
    Build and insert the complete document into flow_leads.

    Top-level fields sourced directly from documented payload paths:
      - wa_message_id     : messages[].id
      - wa_phone          : messages[].from
      - wa_display_name   : contacts[].profile.name  (matched by wa_id)
      - message_timestamp : messages[].timestamp (unix string → stored as-is)
      - phone_number_id   : metadata.phone_number_id
      - All flow fields from response_json (TATTI complete action payload)
    """
    wa_phone = message.get("from", "")

    doc = {
        # ── From messages[] ───────────────────────────────────────────────
        "wa_message_id"     : message.get("id"),
        "wa_phone"          : wa_phone,
        "message_timestamp" : message.get("timestamp"),  # unix epoch string from Meta

        # ── From contacts[] ───────────────────────────────────────────────
        "wa_display_name"   : get_contact_name(contacts, wa_phone),

        # ── From metadata ─────────────────────────────────────────────────
        "phone_number_id"   : metadata.get("phone_number_id"),

        # ── Extracted flow fields (from response_json) ────────────────────
        # Keys match the TATTI Flow JSON "complete" action payload exactly
        "full_name"         : flow_data.get("full_name"),
        "email"             : flow_data.get("email"),
        "qualification"     : flow_data.get("qualification"),
        "current_status"    : flow_data.get("current_status"),
        "preferred_batch"   : flow_data.get("preferred_batch"),
        "mode_of_study"     : flow_data.get("mode_of_study"),
        "category"          : flow_data.get("category"),
        "degree"            : flow_data.get("degree"),
        "confirmed"         : flow_data.get("confirmed"),
        "flow_token"        : flow_data.get("flow_token"),  # always sent by Meta

        # ── Server timestamp ──────────────────────────────────────────────
        "received_at"       : datetime.now(timezone.utc),

        # ── Raw payloads (full audit trail) ───────────────────────────────
        "raw_flow_payload"  : flow_data,    # parsed response_json dict
        "raw_webhook"       : raw_webhook,  # complete Meta POST body
    }

    try:
        leads_col.insert_one(doc)
        print(
            f"✅ Lead saved → "
            f"name={doc.get('full_name')} | "
            f"phone={wa_phone} | "
            f"degree={doc.get('degree')} | "
            f"confirmed={doc.get('confirmed')}"
        )
    except DuplicateKeyError:
        print(f"⚠️  Duplicate ignored — message_id already stored: {message.get('id')}")
    except Exception as e:
        print(f"❌ MongoDB insert error: {e}")


# ── Flow Endpoint ─────────────────────────────────────────────────────────────

@app.route("/flow", methods=["POST"])
def flow_endpoint():
    """
    WhatsApp Flow Endpoint — called by Meta mid-flow for data_exchange actions.

    This is a SEPARATE endpoint from /webhook.
    Register this URL in Meta: Flow Builder → your flow → Endpoint URL → <your-domain>/flow

    Encryption is auto-detected:
      - If request body contains "encrypted_flow_data" → ENCRYPTED mode (production)
      - Otherwise → UNENCRYPTED mode (development, encryption toggled off in Flow Builder)

    Handles three action types:
      ping          → Meta health check sent when you save the endpoint URL
      init          → Sent when the flow is first opened by the user
      data_exchange → Sent when a screen's footer uses "name": "data_exchange"
                      Currently fired from the CATEGORY screen.

    Routing logic (CATEGORY data_exchange):
      category == "degree"                          → DEGREE_SELECTION
      category in skill/internship/study_abroad/other → CONFIRMATION (skip degree screens)

    IMPORTANT — routing_model in your flow JSON must allow all target screens:
      "CATEGORY": ["DEGREE_SELECTION", "CONFIRMATION"]   ← add CONFIRMATION here

    Error handling:
      HTTP 421 → returned when decryption fails (Meta's expected error code for this)
    """
    raw_body = request.get_json(silent=True) or {}

    print("=" * 60)
    print("📥 FLOW ENDPOINT POST received")

    # ── Detect encrypted vs unencrypted mode ─────────────────────────────────
    is_encrypted = "encrypted_flow_data" in raw_body

    if is_encrypted:
        print("🔐 Encrypted request detected — decrypting...")
        try:
            body = decrypt_flow_request(
                raw_body["encrypted_flow_data"],
                raw_body["encrypted_aes_key"],
                raw_body["initial_vector"],
            )
            print("🔓 Decrypted request body:")
            print(json.dumps(body, indent=2))
        except Exception as e:
            # Meta expects HTTP 421 when your endpoint fails to decrypt.
            # This usually means the public key on Meta doesn't match your private key.
            print(f"❌ Decryption failed: {e}")
            return "", 421

        # Keep the original encrypted fields so we can encrypt the response
        aes_key_b64 = raw_body["encrypted_aes_key"]
        iv_b64      = raw_body["initial_vector"]

    else:
        # Unencrypted dev mode — Flow Builder → Settings → Endpoint Encryption OFF
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

    # ── Helper: build and send response (encrypted or plain) ─────────────────
    def send_response(response_dict: dict):
        """
        In encrypted mode: AES-GCM encrypt the response dict and return as plain text.
        In unencrypted mode: return as normal JSON.
        """
        if is_encrypted:
            encrypted_response = encrypt_flow_response(response_dict, aes_key_b64, iv_b64)
            return app.response_class(
                response=encrypted_response,
                status=200,
                mimetype="text/plain"
            )
        return jsonify(response_dict), 200

    # ── 1. Ping — Meta health check ───────────────────────────────────────────
    # Meta pings your endpoint when you first save its URL in the Flow Builder.
    # Must respond with {"version": "3.0", "data": {"status": "active"}}
    if action == "ping":
        print("🏓 Ping received — responding active")
        return send_response({
            "version": version,
            "data": {"status": "active"}
        })

    # ── 2. Init — flow opened by user ─────────────────────────────────────────
    # Sent once when the flow opens. Since WELCOME is fully static with no
    # dynamic data, we return an empty data object — no screen navigation needed.
    if action == "init":
        print("🚀 Init received — flow opened (static WELCOME, returning empty data)")
        return send_response({
            "version": version,
            "data": {}
        })

    # ── 3. data_exchange from CATEGORY screen ─────────────────────────────────
    # Fired when the user taps "Continue" on the CATEGORY screen.
    # Payload contains all fields collected up to that point.
    # We decide which screen to show next based on the selected category.
    if action == "data_exchange" and screen == "CATEGORY":
        category = data.get("category", "")

        print(
            f"🔄 CATEGORY data_exchange — "
            f"category={category} | "
            f"name={data.get('full_name')} | "
            f"email={data.get('email')}"
        )

        # Fields to forward to every possible next screen.
        # Must match the `data` declarations in the target screen exactly.
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
            # Show the degree picker screen
            print("➡️  Routing to DEGREE_SELECTION")
            return send_response({
                "version" : version,
                "screen"  : "DEGREE_SELECTION",
                "data"    : forwarded_data,
            })

        else:
            # skill / internship / study_abroad / other
            # Skip degree-related screens — go straight to CONFIRMATION.
            # "degree" must be included because CONFIRMATION's data block declares it.
            print(f"➡️  Non-degree category '{category}' — routing straight to CONFIRMATION")
            return send_response({
                "version" : version,
                "screen"  : "CONFIRMATION",
                "data"    : {**forwarded_data, "degree": ""},
            })

    # ── Fallback — log and return gracefully ──────────────────────────────────
    print(f"⚠️  Unhandled — action='{action}' | screen='{screen}'")
    return send_response({
        "version" : version,
        "data"    : {"error": f"unhandled action '{action}' on screen '{screen}'"},
    })


# ── Webhook Routes ────────────────────────────────────────────────────────────

@app.route("/webhook", methods=["GET"])
def verify():
    """
    Meta sends a GET to verify the webhook endpoint.
    Must return hub.challenge as plain text with 200.
    """
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
    Per Meta docs, the same endpoint receives both:
      - value.messages[]  → actual user messages (what we want)
      - value.statuses[]  → delivery/read receipts (we skip these)

    For TATTI flows, this fires once the user hits Submit on the CONFIRMATION
    screen (the "complete" action). The full flow payload arrives inside
    messages[].interactive.nfm_reply.response_json as a JSON string.
    """
    raw_webhook = request.get_json(silent=True) or {}

    # Log every incoming POST so you can see what Meta sends in Render logs
    print("=" * 60)
    print("📥 WEBHOOK POST received:")
    print(json.dumps(raw_webhook, indent=2))
    print("=" * 60)

    try:
        # Per docs: entry is always a list; iterate all entries
        for entry in raw_webhook.get("entry", []):
            waba_id = entry.get("id")

            # Per docs: changes is a list inside each entry
            for change in entry.get("changes", []):
                field    = change.get("field")  # should always be "messages"
                value    = change.get("value", {})

                metadata = value.get("metadata", {})
                contacts = value.get("contacts", [])  # user profile info
                messages = value.get("messages", [])  # actual messages
                statuses = value.get("statuses", [])  # delivery receipts

                print(
                    f"🔍 WABA={waba_id} | field={field} | "
                    f"messages={len(messages)} | statuses={len(statuses)}"
                )

                # ── Skip delivery/read receipts — they are NOT messages ────
                if statuses and not messages:
                    for s in statuses:
                        print(
                            f"   ↳ status event: "
                            f"id={s.get('id')} "
                            f"status={s.get('status')} "
                            f"recipient={s.get('recipient_id')}"
                        )
                    print("⏭️  Skipping — this is a status update, not a message")
                    continue

                # ── Process each message ──────────────────────────────────
                for message in messages:
                    msg_id   = message.get("id")
                    msg_from = message.get("from")
                    msg_type = message.get("type")
                    msg_ts   = message.get("timestamp")

                    print(
                        f"📨 message: id={msg_id} | "
                        f"from={msg_from} | "
                        f"type={msg_type} | "
                        f"timestamp={msg_ts}"
                    )

                    # Per docs: flow responses come as type="interactive"
                    if msg_type != "interactive":
                        print(f"⏭️  Skipping — type is '{msg_type}', not 'interactive'")
                        continue

                    # Per docs: inside interactive, type must be "nfm_reply" for flow responses
                    interactive      = message.get("interactive", {})
                    interactive_type = interactive.get("type")
                    print(f"🔗 interactive.type = {interactive_type}")

                    if interactive_type != "nfm_reply":
                        print(
                            f"⏭️  Skipping — "
                            f"interactive.type is '{interactive_type}', not 'nfm_reply'"
                        )
                        continue

                    # Per docs: nfm_reply has name="flow", body="Sent", response_json=<JSON string>
                    nfm_reply         = interactive.get("nfm_reply", {})
                    nfm_name          = nfm_reply.get("name")       # should be "flow"
                    nfm_body          = nfm_reply.get("body")       # should be "Sent"
                    response_json_str = nfm_reply.get("response_json", "{}")

                    print(f"📋 nfm_reply.name={nfm_name} | body={nfm_body}")
                    print(f"📋 response_json (raw string): {response_json_str}")

                    # Parse the response_json string into a dict
                    try:
                        flow_data = json.loads(response_json_str)
                        print(f"✅ Parsed flow_data keys: {list(flow_data.keys())}")
                    except json.JSONDecodeError as e:
                        print(f"❌ Failed to parse response_json: {e}")
                        continue

                    # Save to MongoDB
                    save_lead(message, contacts, metadata, flow_data, raw_webhook)

    except Exception as e:
        print(f"❌ Webhook processing error: {e}")

    # Always return 200 immediately — Meta retries if it gets anything else
    return jsonify({"status": "ok"}), 200


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(port=5000, debug=True)