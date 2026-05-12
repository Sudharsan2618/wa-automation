"""
TATTI WhatsApp Flow Webhook — app.py

═══════════════════════════════════════════════════════════════
SAVE STRATEGY — Why we don't rely on /webhook for primary data
═══════════════════════════════════════════════════════════════
Meta's "complete" action POSTs to /webhook, but this call is
unreliable on hosted platforms (Render cold starts, Meta retry
windows, etc). Instead we use a two-phase upsert by flow_token:

  Phase 1  ──  /flow  ──  COURSE_DETAILS  data_exchange
    • Fired when user taps "Proceed" after reading course info.
    • At this point we already have ALL meaningful data:
        full_name, email, qualification, current_status, degree
    • Saved immediately with status="in_progress".
    • User is then routed to CONFIRMATION screen.

  Phase 2  ──  /webhook  ──  CONFIRMATION  complete  (bonus)
    • Fired when user taps "Submit" on CONFIRMATION.
    • Adds: confirmed, wa_phone, wa_message_id, wa_display_name.
    • Upserts the same document by flow_token → status="completed".
    • If webhook never fires, Phase 1 data is still fully usable.

Flow path (CATEGORY screen removed — only degree programmes):
  WELCOME → LEAD_DETAILS → DEGREE_SELECTION → COURSE_DETAILS
          → CONFIRMATION

Updated LEAD_DETAILS fields:
  qualification  : Group Studied in 12th
                   (computer_maths | bio_maths | pure_science |
                    commerce | ca | others)
  current_status : student | parent
  REMOVED        : preferred_batch, mode_of_study

═══════════════════════════════════════════════════════════════
Official webhook payload reference:
  entry[].changes[].value.contacts[].wa_id      → user WA ID
  entry[].changes[].value.contacts[].profile.name
  entry[].changes[].value.messages[].id         → wamid
  entry[].changes[].value.messages[].from       → phone number
  entry[].changes[].value.messages[].timestamp
  entry[].changes[].value.messages[].interactive.nfm_reply
    .response_json                               → JSON string
  entry[].changes[].value.statuses[]            → skip these

/flow endpoint decrypted request keys:
  version, action (ping | init | data_exchange),
  flow_token, screen, data{}
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
PRIVATE_KEY_PASSPHRASE = os.getenv("PRIVATE_KEY_PASSPHRASE", "")  # empty if key has no password

# ── MongoDB Setup ─────────────────────────────────────────────────────────────

mongo_client = MongoClient(MONGO_URI)
db           = mongo_client["whatsapp-automation"]
leads_col    = db["flow_leads"]

# sparse=True → in_progress docs (no wa_message_id yet) don't collide on the unique index
leads_col.create_index("wa_message_id", unique=True, sparse=True)

# Non-unique — used as the upsert match key in both phases
leads_col.create_index("flow_token")

print("✅ MongoDB connected — whatsapp-automation.flow_leads")

# ── RSA / AES Encryption Helpers ─────────────────────────────────────────────

def load_private_key():
    """
    Load RSA private key from ./private_rsa.pem.
    Set PRIVATE_KEY_PASSPHRASE in .env if your key was generated with -des3.
    Leave empty (default) if the key has no password.
    """
    with open("./private_rsa.pem", "rb") as f:
        passphrase = PRIVATE_KEY_PASSPHRASE.encode() if PRIVATE_KEY_PASSPHRASE else None
        return load_pem_private_key(f.read(), password=passphrase, backend=default_backend())


def decrypt_flow_request(
    encrypted_flow_data: str,
    encrypted_aes_key: str,
    initial_vector: str,
) -> dict:
    """
    Decrypt Meta's Flow endpoint request.

    Meta's scheme:
      1. A random AES-128-GCM key is RSA-OAEP-SHA256 encrypted
         with your business public key  →  encrypted_aes_key
      2. The JSON body is AES-GCM encrypted  →  encrypted_flow_data
         (last 16 bytes of the decoded value = GCM auth tag)
      3. We reverse both steps using the RSA private key.

    Returns the decrypted body dict.
    Raises on any failure — caller must return HTTP 421.
    """
    pk = load_private_key()

    # Step 1 — RSA-OAEP decrypt the AES key
    aes_key = pk.decrypt(
        base64.b64decode(encrypted_aes_key),
        OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None),
    )

    # Step 2 — AES-GCM decrypt the body
    iv             = base64.b64decode(initial_vector)
    raw            = base64.b64decode(encrypted_flow_data)
    encrypted_body = raw[:-16]   # ciphertext
    auth_tag       = raw[-16:]   # GCM authentication tag (always last 16 bytes)

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, auth_tag),
        backend=default_backend(),
    ).decryptor()

    plaintext = decryptor.update(encrypted_body) + decryptor.finalize()
    return json.loads(plaintext.decode("utf-8"))


def encrypt_flow_response(
    response_body: dict,
    encrypted_aes_key: str,
    initial_vector: str,
) -> str:
    """
    Encrypt the response back to Meta using the SAME AES key + bit-flipped IV.

    Meta's spec:
      - AES key: same as the request (decrypt with RSA private key first).
      - IV: every byte XOR 0xFF (all bits flipped).
      - Output: base64( ciphertext + 16-byte GCM auth tag )
      - Content-Type of the HTTP response must be text/plain.
    """
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


# ── MongoDB Save Helpers ──────────────────────────────────────────────────────

def upsert_lead_from_flow(flow_token: str, data: dict):
    """
    Phase 1 — PRIMARY SAVE.
    Called from /flow when COURSE_DETAILS data_exchange fires.

    By COURSE_DETAILS we have ALL the fields we care about:
      full_name, email, qualification, current_status, degree

    Uses update_one + upsert=True keyed on flow_token so that:
      • First call  → inserts a new document (status = in_progress).
      • Retry calls → updates the same document without duplicating.

    $setOnInsert writes created_at only on the very first insert.
    This runs BEFORE we return the routing response to Meta, so
    the data is persisted even if the user closes the flow immediately.
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
                    "degree"          : data.get("degree"),
                    "status"          : "in_progress",
                    "last_updated_at" : now,
                },
                "$setOnInsert": {
                    "created_at": now,
                },
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
        # Log but don't raise — we still want to return the routing response
        print(f"❌ upsert_lead_from_flow error: {e}")


def get_contact_name(contacts: list, wa_phone: str) -> str:
    """Return the WhatsApp display name for wa_phone from the contacts list."""
    for c in contacts:
        if c.get("wa_id") == wa_phone:
            return c.get("profile", {}).get("name", "")
    return contacts[0].get("profile", {}).get("name", "") if contacts else ""


def complete_lead_from_webhook(
    message: dict,
    contacts: list,
    metadata: dict,
    flow_data: dict,
    raw_webhook: dict,
):
    """
    Phase 2 — BONUS SAVE (best-effort).
    Called from /webhook when CONFIRMATION complete action fires.

    Upserts by flow_token to update the Phase 1 document with:
      confirmed, wa_phone, wa_message_id, wa_display_name,
      phone_number_id, message_timestamp, status="completed",
      and a full raw audit trail.

    If Phase 1 doc is missing (edge case where /flow was never
    called, or flow_token is absent) → inserts a complete document.
    """
    wa_phone   = message.get("from", "")
    flow_token = flow_data.get("flow_token", "")
    now        = datetime.now(timezone.utc)

    update_fields = {
        # ── WhatsApp identity (only available via webhook) ────────────────
        "wa_message_id"    : message.get("id"),
        "wa_phone"         : wa_phone,
        "wa_display_name"  : get_contact_name(contacts, wa_phone),
        "phone_number_id"  : metadata.get("phone_number_id"),
        "message_timestamp": message.get("timestamp"),

        # ── Final answer from CONFIRMATION screen ─────────────────────────
        "confirmed"        : flow_data.get("confirmed"),

        # ── Re-assert all flow fields (handles Phase 1 missing edge case) ─
        "flow_token"       : flow_token,
        "full_name"        : flow_data.get("full_name"),
        "email"            : flow_data.get("email"),
        "qualification"    : flow_data.get("qualification"),
        "current_status"   : flow_data.get("current_status"),
        "degree"           : flow_data.get("degree"),

        # ── Status + timestamps ───────────────────────────────────────────
        "status"           : "completed",
        "received_at"      : now,
        "last_updated_at"  : now,

        # ── Full raw audit trail ──────────────────────────────────────────
        "raw_flow_payload" : flow_data,
        "raw_webhook"      : raw_webhook,
    }

    # Prefer flow_token match; fall back to wa_message_id if token missing
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
                f"degree={flow_data.get('degree')} | "
                f"confirmed={flow_data.get('confirmed')}"
            )
        else:
            print(
                f"✅ Phase 2 (updated) → "
                f"flow_token={flow_token} | "
                f"confirmed={flow_data.get('confirmed')}"
            )

    except DuplicateKeyError:
        print(f"⚠️  Duplicate — wa_message_id already stored: {message.get('id')}")
    except Exception as e:
        print(f"❌ complete_lead_from_webhook error: {e}")


# ── /flow Endpoint ────────────────────────────────────────────────────────────

@app.route("/flow", methods=["POST"])
def flow_endpoint():
    """
    Meta calls this URL mid-flow whenever a screen has a data_exchange action.

    Register at: Flow Builder → your flow → Endpoint URL → <domain>/flow

    ┌─────────────────────────────────────────────────────┐
    │  action = ping          →  health check response    │
    │  action = init          →  flow opened (WELCOME)    │
    │  action = data_exchange │                           │
    │    screen = COURSE_DETAILS  →  PRIMARY SAVE + route │
    │                             to CONFIRMATION         │
    └─────────────────────────────────────────────────────┘

    Encryption auto-detected:
      "encrypted_flow_data" key present  →  production (encrypted)
      absent                              →  dev mode (plain JSON)

    HTTP 421 returned on decryption failure (Meta's required error code).
    """
    raw_body = request.get_json(silent=True) or {}

    print("=" * 60)
    print("📥 /flow POST received")

    # ── Detect mode ───────────────────────────────────────────────────────────
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
            return "", 421  # Meta expects exactly 421 on decryption failure
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

    # ── Unified response helper ───────────────────────────────────────────────
    def send_response(payload: dict):
        """
        Encrypt and return text/plain in production.
        Return JSON in dev mode.
        """
        if is_encrypted:
            encrypted = encrypt_flow_response(payload, aes_key_b64, iv_b64)
            return app.response_class(
                response=encrypted,
                status=200,
                mimetype="text/plain",
            )
        return jsonify(payload), 200

    # ── 1. Ping — health check ────────────────────────────────────────────────
    # Meta sends this when you save/update the endpoint URL in Flow Builder.
    # Must reply {"version": "3.0", "data": {"status": "active"}} within ~3 s.
    if action == "ping":
        print("🏓 Ping — responding active")
        return send_response({"version": version, "data": {"status": "active"}})

    # ── 2. Init — flow opened ─────────────────────────────────────────────────
    # Sent once when the user opens the flow. WELCOME is fully static so we
    # return an empty data object — no navigation or dynamic content needed.
    if action == "init":
        print("🚀 Init — WELCOME is static, returning {}")
        return send_response({"version": version, "data": {}})

    # ── 3. data_exchange — COURSE_DETAILS screen ──────────────────────────────
    # This is our PRIMARY SAVE POINT.
    #
    # Triggered when the user taps "Proceed" on COURSE_DETAILS.
    # At this point the payload already contains every field we need:
    #   full_name, email, qualification, current_status, degree
    #
    # We save to MongoDB FIRST (before replying), then route to CONFIRMATION.
    # Even if the user closes WhatsApp after this, data is in the DB.
    if action == "data_exchange" and screen == "COURSE_DETAILS":
        print(
            f"🔄 COURSE_DETAILS data_exchange — "
            f"name={data.get('full_name')} | "
            f"email={data.get('email')} | "
            f"degree={data.get('degree')}"
        )

        # ── PRIMARY SAVE (Phase 1) — runs before we reply to Meta ────────
        upsert_lead_from_flow(flow_token, data)

        # ── Route to CONFIRMATION — pass all collected data through ───────
        # CONFIRMATION's data block declares all these fields, so they must
        # all be present in this response.
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

    # ── Fallback ──────────────────────────────────────────────────────────────
    print(f"⚠️  Unhandled — action='{action}' | screen='{screen}'")
    return send_response({
        "version": version,
        "data"   : {"error": f"unhandled action='{action}' screen='{screen}'"},
    })


# ── /webhook Endpoint — verification ─────────────────────────────────────────

@app.route("/webhook", methods=["GET"])
def verify():
    """
    Meta sends a GET to verify the webhook URL.
    Must echo hub.challenge as plain text with HTTP 200.
    """
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
    """
    Receives all WhatsApp Cloud API events (messages + status updates).

    For TATTI flows this fires when the user taps Submit on CONFIRMATION
    (the "complete" action). The full payload is in:
      messages[].interactive.nfm_reply.response_json  (a JSON string)

    This is Phase 2 (bonus save) — upserts the in_progress document
    created in Phase 1 with confirmed + WhatsApp identity fields.

    NOTE: Primary data is already saved in Phase 1 (/flow COURSE_DETAILS).
    If this endpoint is never called, Phase 1 data is complete and usable.

    Always returns HTTP 200 immediately — Meta retries on any other code.
    """
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

                # ── Skip delivery / read receipts ─────────────────────────
                if statuses and not messages:
                    for s in statuses:
                        print(
                            f"   ↳ status: id={s.get('id')} "
                            f"status={s.get('status')} "
                            f"recipient={s.get('recipient_id')}"
                        )
                    print("⏭️  Status update — skipping")
                    continue

                # ── Process messages ──────────────────────────────────────
                for message in messages:
                    msg_id   = message.get("id")
                    msg_from = message.get("from")
                    msg_type = message.get("type")
                    msg_ts   = message.get("timestamp")

                    print(
                        f"📨 id={msg_id} | from={msg_from} | "
                        f"type={msg_type} | ts={msg_ts}"
                    )

                    # Flow replies come as type = "interactive"
                    if msg_type != "interactive":
                        print(f"⏭️  type='{msg_type}' — not interactive, skipping")
                        continue

                    interactive      = message.get("interactive", {})
                    interactive_type = interactive.get("type")
                    print(f"🔗 interactive.type={interactive_type}")

                    # Flow replies specifically use nfm_reply
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

                    # ── Phase 2 bonus save ────────────────────────────────
                    complete_lead_from_webhook(
                        message, contacts, metadata, flow_data, raw_webhook
                    )

    except Exception as e:
        print(f"❌ Webhook processing error: {e}")

    # Always 200 — Meta retries on anything else
    return jsonify({"status": "ok"}), 200


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(port=5000, debug=True)