from flask import Flask, request, jsonify
import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
VERIFY_TOKEN = "Sunflower@2618"

BASE_URL = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"
HEADERS = {
    "Authorization": f"Bearer {ACCESS_TOKEN}",
    "Content-Type": "application/json"
}

def save_to_log(data):
    # This saves the leads to a local file so you don't lose them
    with open("leads.txt", "a") as f:
        f.write(json.dumps(data) + "\n")

# ── Webhook Routes ───────────────────────────────

@app.route("/webhook", methods=["GET"])
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200
    return "Forbidden", 403

@app.route("/webhook", methods=["POST"])
def webhook_listener():
    data = request.get_json()

    # Navigate through the Meta JSON structure
    try:
        if data.get("entry"):
            for entry in data["entry"]:
                for change in entry.get("changes", []):
                    value = change.get("value")
                    if value and "messages" in value:
                        for message in value["messages"]:
                            
                            # 🎯 CHECK IF MESSAGE IS A FLOW RESPONSE
                            if message.get("type") == "interactive":
                                interactive = message.get("interactive", {})
                                
                                if interactive.get("type") == "nfm_reply":
                                    # This is your TATTI Flow data!
                                    response_json_str = interactive["nfm_reply"]["response_json"]
                                    flow_data = json.loads(response_json_str)
                                    
                                    # Extract data based on your Flow JSON keys
                                    lead_info = {
                                        "sender_phone": message.get("from"),
                                        "name": flow_data.get("full_name"),
                                        "email": flow_data.get("email"),
                                        "degree": flow_data.get("degree_choice"),
                                        "status": flow_data.get("final_choice")
                                    }
                                    
                                    print(f"✅ New Lead Received: {lead_info['name']} for {lead_info['degree']}")
                                    save_to_log(lead_info)

    except Exception as e:
        print(f"Error parsing webhook: {e}")

    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(port=5000, debug=True)