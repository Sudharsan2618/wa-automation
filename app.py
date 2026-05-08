from flask import Flask, request, jsonify
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
VERIFY_TOKEN = "Sunflower@2618"  # you choose this string

BASE_URL = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"
HEADERS = {
    "Authorization": f"Bearer {ACCESS_TOKEN}",
    "Content-Type": "application/json"
}

def send(payload):
    response = requests.post(BASE_URL, headers=HEADERS, json=payload)
    return response.json()

# ── All your message functions ──────────────────

def send_category_list(to):
    send({
        "messaging_product": "whatsapp",
        "to": to,
        "type": "interactive",
        "interactive": {
            "type": "list",
            "header": {"type": "text", "text": "🎓 TATTI Learning Hub"},
            "body": {"text": "Welcome! Please select a category below 👇"},
            "footer": {"text": "Choose what interests you most"},
            "action": {
                "button": "Choose Category",
                "sections": [{
                    "title": "Course Categories",
                    "rows": [
                        {"id": "cat_degree", "title": "Degree", "description": "UG degree programs"},
                        {"id": "cat_skill", "title": "Skill", "description": "Skill-based courses"},
                        {"id": "cat_internship", "title": "Internship / Placement", "description": "Get placed in top companies"},
                        {"id": "cat_abroad", "title": "Study Abroad", "description": "International programs"},
                        {"id": "cat_other", "title": "Other", "description": "Explore more options"}
                    ]
                }]
            }
        }
    })

def send_degree_list(to):
    send({
        "messaging_product": "whatsapp",
        "to": to,
        "type": "interactive",
        "interactive": {
            "type": "list",
            "header": {"type": "text", "text": "🎓 Degree Programs"},
            "body": {"text": "Which degree would you like to know more about? 👇"},
            "footer": {"text": "Select a course to see details"},
            "action": {
                "button": "View Courses",
                "sections": [{
                    "title": "Our Degree Programs",
                    "rows": [
                        {"id": "course_film", "title": "B.Sc Film & TV", "description": "Filmmaking, directing, editing"},
                        {"id": "course_fintech", "title": "B.Com FinTech & AI", "description": "Digital banking & AI"},
                        {"id": "course_energy", "title": "B.Sc Renewable Energy", "description": "Solar, wind & green tech"}
                    ]
                }]
            }
        }
    })

COURSE_DETAILS = {
    "course_film": {
        "title": "🎬 B.Sc Film & TV Production",
        "body": "Your entry into movies, TV, and OTT.\n\n✅ Filmmaking & Directing\n✅ Shooting & Editing\n✅ Script Writing\n✅ Real content creation\n\nPerfect for creative career in media! 🎥"
    },
    "course_fintech": {
        "title": "💳 B.Com FinTech & AI",
        "body": "Commerce + Technology + AI combined.\n\n✅ Digital Banking & Finance\n✅ How money moves through apps\n✅ AI in business 📊\n✅ Career in banking & startups\n\nThe smartest career choice for the digital era!"
    },
    "course_energy": {
        "title": "🌱 B.Sc Renewable Energy",
        "body": "Clean energy from solar, wind & hydro.\n\n✅ Green Technology\n✅ Energy Systems\n✅ Sustainable Solutions\n✅ Build a cleaner planet 🌍\n\nPerfect for science & environment lovers!"
    }
}

def send_course_details(to, course_id):
    course = COURSE_DETAILS.get(course_id)
    if not course:
        return
    send({
        "messaging_product": "whatsapp",
        "to": to,
        "type": "interactive",
        "interactive": {
            "type": "button",
            "header": {"type": "text", "text": course["title"]},
            "body": {"text": course["body"]},
            "footer": {"text": "Does this course match your interest?"},
            "action": {
                "buttons": [
                    {"type": "reply", "reply": {"id": f"yes_{course_id}", "title": "✅ YES, Interested"}},
                    {"type": "reply", "reply": {"id": f"no_{course_id}", "title": "❌ NO, Show Others"}}
                ]
            }
        }
    })

def send_yes(to):
    send({
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": "🎉 Thank you for confirming!\n\nYour details have been forwarded to our academic counselor. They will contact you shortly! 🚀\n\n*TATTI Learning Hub*\n📞 9884170589"}
    })

def send_no(to):
    send({
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": "All good! 😊\n\nThanks for checking it out. We'll be here whenever you're ready!\n\n*TATTI Learning Hub*\n📞 9884170589"}
    })

# ── Webhook Routes ───────────────────────────────

# Meta verification handshake
@app.route("/webhook", methods=["GET"])
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("Webhook verified!")
        return challenge, 200
    return "Forbidden", 403


# Receive incoming messages
@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json()

    try:
        entry = data["entry"][0]["changes"][0]["value"]
        messages = entry.get("messages")

        if not messages:
            return jsonify({"status": "no message"}), 200

        msg = messages[0]
        from_number = msg["from"]
        msg_type = msg["type"]

        reply_id = None
        reply_text = None

        # Extract reply ID and text based on message type
        if msg_type == "text":
            reply_text = msg["text"]["body"].strip().lower()

        elif msg_type == "interactive":
            interactive = msg["interactive"]
            if interactive["type"] == "list_reply":
                reply_id = interactive["list_reply"]["id"]
                reply_text = interactive["list_reply"]["title"]
            elif interactive["type"] == "button_reply":
                reply_id = interactive["button_reply"]["id"]
                reply_text = interactive["button_reply"]["title"]

        # ── Route the reply ──────────────────────
        if reply_text and reply_text.lower() in ["hi", "hello", "hey", "start"]:
            send_category_list(from_number)

        elif reply_id == "cat_degree":
            send_degree_list(from_number)

        elif reply_id in ["cat_skill", "cat_internship", "cat_abroad", "cat_other"]:
            send({"messaging_product": "whatsapp", "to": from_number, "type": "text",
                  "text": {"body": "Thanks for your interest! Our counselor will reach out to you shortly with details. 📞\n\n*TATTI Learning Hub* — 9884170589"}})

        elif reply_id in ["course_film", "course_fintech", "course_energy"]:
            send_course_details(from_number, reply_id)

        elif reply_id and reply_id.startswith("yes_"):
            send_yes(from_number)

        elif reply_id and reply_id.startswith("no_"):
            send_category_list(from_number)

    except Exception as e:
        print("Error:", e)

    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(port=5000, debug=True)