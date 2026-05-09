from flask import Flask, request, jsonify
import os
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

load_dotenv()

app = Flask(__name__)

# ── Config ───────────────────────────────────────────────────────────────────

ACCESS_TOKEN     = os.getenv("ACCESS_TOKEN")
PHONE_NUMBER_ID  = os.getenv("PHONE_NUMBER_ID")
VERIFY_TOKEN     = "Sunflower@2618"

MONGO_URI        = os.getenv("MONGO_URI")

# ── MongoDB Setup ─────────────────────────────────────────────────────────────

mongo_client = MongoClient(MONGO_URI)
db           = mongo_client["whatsapp-automation"]
leads_col    = db["flow_leads"]

# Unique index on wa_message_id to prevent duplicate inserts on Meta retries
leads_col.create_index("wa_message_id", unique=True, sparse=True)

print("✅ Connected to MongoDB — db: whatsapp-automation, collection: flow_leads")

# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_lead(flow_data: dict, message: dict) -> dict:
    """
    Pull the known fields from the flow payload.
    Matches the keys used in your TATTI Flow JSON 'complete' action payload.
    """
    return {
        "full_name"      : flow_data.get("full_name"),
        "email"          : flow_data.get("email"),
        "qualification"  : flow_data.get("qualification"),
        "current_status" : flow_data.get("current_status"),
        "preferred_batch": flow_data.get("preferred_batch"),
        "mode_of_study"  : flow_data.get("mode_of_study"),
        "category"       : flow_data.get("category"),
        "degree"         : flow_data.get("degree"),
        "confirmed"      : flow_data.get("confirmed"),   # "yes" / "no"
    }


def save_lead(message: dict, flow_data: dict, raw_webhook: dict):
    """
    Insert one document into flow_leads with:
      - extracted fields  (top-level, easy to query)
      - raw_flow_payload  (the parsed flow JSON)
      - raw_webhook       (the full Meta webhook body for debugging)
    """
    doc = {
        # ── Identity ─────────────────────────────────────────────────────
        "wa_message_id" : message.get("id"),
        "wa_phone"      : message.get("from"),
        "timestamp"     : datetime.now(timezone.utc),

        # ── Extracted lead fields ─────────────────────────────────────────
        **extract_lead(flow_data, message),

        # ── Raw payloads (for audit / re-processing) ──────────────────────
        "raw_flow_payload" : flow_data,
        "raw_webhook"      : raw_webhook,
    }

    try:
        leads_col.insert_one(doc)
        print(f"✅ Lead saved → {doc.get('full_name')} | {doc.get('wa_phone')} | {doc.get('degree')}")
    except DuplicateKeyError:
        print(f"⚠️  Duplicate ignored (message_id already stored): {message.get('id')}")
    except Exception as e:
        print(f"❌ MongoDB insert error: {e}")


# ── Webhook Routes ────────────────────────────────────────────────────────────

@app.route("/webhook", methods=["GET"])
def verify():
    mode      = request.args.get("hub.mode")
    token     = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("✅ Webhook verified by Meta")
        return challenge, 200
    return "Forbidden", 403


@app.route("/webhook", methods=["POST"])
def webhook_listener():
    raw_webhook = request.get_json(silent=True) or {}

    try:
        for entry in raw_webhook.get("entry", []):
            for change in entry.get("changes", []):
                value    = change.get("value", {})
                messages = value.get("messages", [])

                for message in messages:
                    if message.get("type") != "interactive":
                        continue

                    interactive = message.get("interactive", {})
                    if interactive.get("type") != "nfm_reply":
                        continue

                    # ── Parse the flow response JSON ──────────────────────
                    response_json_str = interactive["nfm_reply"].get("response_json", "{}")
                    try:
                        flow_data = json.loads(response_json_str)
                    except json.JSONDecodeError as e:
                        print(f"❌ Failed to parse flow JSON: {e}")
                        continue

                    # ── Save to MongoDB ───────────────────────────────────
                    save_lead(message, flow_data, raw_webhook)

    except Exception as e:
        print(f"❌ Webhook processing error: {e}")

    # Always return 200 quickly so Meta doesn't retry
    return jsonify({"status": "ok"}), 200


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(port=5000, debug=True)
