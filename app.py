from flask import Flask, request, jsonify
import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configuration
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
VERIFY_TOKEN = "Sunflower@2618"

BASE_URL = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"
HEADERS = {
    "Authorization": f"Bearer {ACCESS_TOKEN}",
    "Content-Type": "application/json"
}

def save_to_log(data):
    """Saves lead information to a local text file."""
    with open("leads.txt", "a") as f:
        f.write(json.dumps(data) + "\n")

# ── Webhook Routes ───────────────────────────────

@app.route("/webhook", methods=["GET"])
def verify():
    """Handles the Meta Webhook verification handshake."""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("✅ Webhook Verified successfully!")
        return challenge, 200
    return "Forbidden", 403

@app.route("/webhook", methods=["POST"])
def webhook_listener():
    """Listens for incoming messages and extracts Flow data."""
    data = request.get_json()

    # Log raw data for debugging if needed
    # print(json.dumps(data, indent=2))

    try:
        if data.get("entry"):
            for entry in data["entry"]:
                for change in entry.get("changes", []):
                    value = change.get("value")
                    if value and "messages" in value:
                        for message in value["messages"]:
                            
                            # 🎯 STEP 1: Check for 'interactive' message type
                            if message.get("type") == "interactive":
                                interactive = message.get("interactive", {})
                                
                                # 🎯 STEP 2: Specifically check for Flow response (nfm_reply)
                                if interactive.get("type") == "nfm_reply":
                                    # Flow data arrives as a stringified JSON
                                    response_json_str = interactive["nfm_reply"]["response_json"]
                                    flow_data = json.loads(response_json_str)
                                    
                                    # 🎯 STEP 3: Map data to your TATTI lead structure
                                    # Ensure these keys match your Flow JSON 'payload' exactly
                                    lead_info = {
                                        "sender_phone": message.get("from"),
                                        "name": flow_data.get("full_name"),
                                        "email": flow_data.get("email"),
                                        "degree": flow_data.get("degree_choice"), # or 'selected_degree'
                                        "timestamp": message.get("timestamp")
                                    }
                                    
                                    print(f"🎯 TATTI LEAD CAPTURED: {lead_info['name']} ({lead_info['degree']})")
                                    save_to_log(lead_info)
                                    
    except Exception as e:
        print(f"❌ Error parsing webhook: {e}")

    # Meta requires a 200 OK response within 10 seconds
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    # Ensure port 5000 is open in Ngrok
    app.run(port=5000, debug=True)