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
"""

from flask import Flask, request, jsonify
import os
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

load_dotenv()

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────


ACCESS_TOKEN     = os.getenv("ACCESS_TOKEN")
PHONE_NUMBER_ID  = os.getenv("PHONE_NUMBER_ID")
VERIFY_TOKEN     = "Sunflower@2618"

MONGO_URI = os.getenv("MONGO_URI")

# ── MongoDB Setup ─────────────────────────────────────────────────────────────

mongo_client = MongoClient(MONGO_URI)
db           = mongo_client["whatsapp-automation"]
leads_col    = db["flow_leads"]

# Unique index on wa_message_id — prevents duplicate inserts on Meta retries
leads_col.create_index("wa_message_id", unique=True, sparse=True)

print("✅ Connected to MongoDB — db: whatsapp-automation, collection: flow_leads")

# ── Helpers ───────────────────────────────────────────────────────────────────

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


def save_lead(message: dict, contacts: list, metadata: dict, flow_data: dict, raw_webhook: dict):
    """
    Build and insert the complete document into flow_leads.

    Top-level fields sourced directly from documented payload paths:
      - wa_message_id   : messages[].id
      - wa_phone        : messages[].from
      - wa_display_name : contacts[].profile.name  (matched by wa_id)
      - message_timestamp : messages[].timestamp (unix string → stored as-is)
      - phone_number_id : metadata.phone_number_id
      - All flow fields from response_json (your TATTI complete action payload)
    """
    wa_phone = message.get("from", "")

    doc = {
        # ── From messages[] ───────────────────────────────────────────────
        "wa_message_id"     : message.get("id"),
        "wa_phone"          : wa_phone,
        "message_timestamp" : message.get("timestamp"),   # unix epoch string from Meta

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
        "raw_flow_payload"  : flow_data,       # parsed response_json dict
        "raw_webhook"       : raw_webhook,     # complete Meta POST body
    }

    try:
        leads_col.insert_one(doc)
        print(f"✅ Lead saved → name={doc.get('full_name')} | phone={wa_phone} | degree={doc.get('degree')} | confirmed={doc.get('confirmed')}")
    except DuplicateKeyError:
        print(f"⚠️  Duplicate ignored — message_id already stored: {message.get('id')}")
    except Exception as e:
        print(f"❌ MongoDB insert error: {e}")


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
                field = change.get("field")   # should always be "messages"
                value = change.get("value", {})

                metadata = value.get("metadata", {})
                contacts = value.get("contacts", [])   # user profile info
                messages = value.get("messages", [])   # actual messages
                statuses = value.get("statuses", [])   # delivery receipts

                print(f"🔍 WABA={waba_id} | field={field} | messages={len(messages)} | statuses={len(statuses)}")

                # ── Skip delivery/read receipts — they are NOT messages ───
                if statuses and not messages:
                    for s in statuses:
                        print(f"   ↳ status event: id={s.get('id')} status={s.get('status')} recipient={s.get('recipient_id')}")
                    print("⏭️  Skipping — this is a status update, not a message")
                    continue

                # ── Process each message ──────────────────────────────────
                for message in messages:
                    msg_id   = message.get("id")
                    msg_from = message.get("from")
                    msg_type = message.get("type")
                    msg_ts   = message.get("timestamp")

                    print(f"📨 message: id={msg_id} | from={msg_from} | type={msg_type} | timestamp={msg_ts}")

                    # Per docs: flow responses come as type="interactive"
                    if msg_type != "interactive":
                        print(f"⏭️  Skipping — type is '{msg_type}', not 'interactive'")
                        continue

                    # Per docs: inside interactive, type must be "nfm_reply" for flow responses
                    interactive      = message.get("interactive", {})
                    interactive_type = interactive.get("type")
                    print(f"🔗 interactive.type = {interactive_type}")

                    if interactive_type != "nfm_reply":
                        print(f"⏭️  Skipping — interactive.type is '{interactive_type}', not 'nfm_reply'")
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