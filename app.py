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
  Request body (unencrypted mode):
    version    → "3.0"
    action     → "ping" | "init" | "data_exchange"
    flow_token → unique token for this flow session
    screen     → current screen ID (present on data_exchange)
    data       → payload sent from the screen's on-click-action (present on data_exchange)

  Response body (for data_exchange):
    version    → echo back "3.0"
    screen     → next screen ID to navigate to
    data       → data object required by the next screen's `data` field declarations

  NOTE: In production Meta encrypts the /flow request body.
        This file handles UNENCRYPTED mode (development/testing).
        To enable unencrypted mode in Meta:
          Flow Builder → your flow → Settings → toggle off "Endpoint Encryption"
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

ACCESS_TOKEN    = os.getenv("ACCESS_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
VERIFY_TOKEN    = "Sunflower@2618"
MONGO_URI       = os.getenv("MONGO_URI")

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


# ── Flow Endpoint — data_exchange ─────────────────────────────────────────────

@app.route("/flow", methods=["POST"])
def flow_endpoint():
    """
    WhatsApp Flow Endpoint — called by Meta mid-flow for data_exchange actions.

    This is a SEPARATE endpoint from /webhook.
    Register this URL in Meta: Flow Builder → your flow → Endpoint URL → <your-domain>/flow

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
    """
    body = request.get_json(silent=True) or {}

    print("=" * 60)
    print("📥 FLOW ENDPOINT POST received:")
    print(json.dumps(body, indent=2))
    print("=" * 60)

    version    = body.get("version", "3.0")
    action     = body.get("action", "")
    screen     = body.get("screen", "")
    flow_token = body.get("flow_token", "")
    data       = body.get("data", {})

    # ── 1. Ping — Meta health check ───────────────────────────────────────────
    # Meta pings your endpoint when you first save its URL in the Flow Builder.
    # Must respond with {"version": "3.0", "data": {"status": "active"}}
    if action == "ping":
        print("🏓 Ping received — responding active")
        return jsonify({
            "version": version,
            "data": {"status": "active"}
        }), 200

    # ── 2. Init — flow opened by user ─────────────────────────────────────────
    # Sent once when the flow opens. Since WELCOME is fully static with no
    # dynamic data, we return an empty data object — no screen navigation needed.
    if action == "init":
        print("🚀 Init received — flow opened (static WELCOME, returning empty data)")
        return jsonify({
            "version": version,
            "data": {}
        }), 200

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

        # Fields to forward to every possible next screen
        # Must match the `data` declarations in the target screen exactly
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
            return jsonify({
                "version" : version,
                "screen"  : "DEGREE_SELECTION",
                "data"    : forwarded_data,
            }), 200

        else:
            # skill / internship / study_abroad / other
            # Skip degree-related screens — go straight to CONFIRMATION.
            # "degree" must be included because CONFIRMATION's data block declares it.
            print(f"➡️  Non-degree category '{category}' — routing straight to CONFIRMATION")
            return jsonify({
                "version" : version,
                "screen"  : "CONFIRMATION",
                "data"    : {**forwarded_data, "degree": ""},
            }), 200

    # ── Fallback — log and return gracefully ──────────────────────────────────
    print(f"⚠️  Unhandled — action='{action}' | screen='{screen}'")
    return jsonify({
        "version" : version,
        "data"    : {"error": f"unhandled action '{action}' on screen '{screen}'"},
    }), 200


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