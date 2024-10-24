import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import requests
from base64 import b64encode

# Load environment variables from .env file
load_dotenv()
# ZOOM_CLIENT_ID=tag_5FgtT9K47SvSYJBNNA
# ZOOM_CLIENT_SECRET=ZZK6dzdjg088HMuRbbSltOiaRr7zjjDD
app = Flask(__name__)

client_id = "tag_5FgtT9K47SvSYJBNNA"
client_secret = "ZZK6dzdjg088HMuRbbSltOiaRr7zjjDD"
verification_token = "6Ti0QEupQVmGLBjCHl5-Og"
slash_command = "suredev"
bot_jid = 'v1irjvn0tltu2vla3bkjyfcw@xmpp.zoom.us'
zoom_verification_code = '6Ti0QEupQVmGLBjCHl5-Og'

# OAuth2 connection
def oauth2_connect():
    token_url = "https://zoom.us/oauth/token"
    auth_str = f"{client_id}:{client_secret}"
    headers = {
        "Authorization": f"Basic {b64encode(auth_str.encode()).decode()}",
    }
    data = {"grant_type": "client_credentials"}
    
    response = requests.post(token_url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        print("Error obtaining OAuth2 token:", response.json())
        return None

# Handle root route
@app.route('/')
def home():
    return 'Welcome to the Vote Chatbot for Zoom!'

# Handle authorize redirect
@app.route('/authorize', methods=['GET'])
def authorize():
    return 'Thanks for installing the Vote Chatbot for Zoom!'

# Handle Zoom slash commands and user actions
@app.route(f'/{slash_command}', methods=['GET'])
def handle_command():
    body = request.json
    headers = request.headers
    try:
        handle_event(body, headers)
        return '', 200
    except Exception as e:
        print("Error handling command:", e)
        return str(e), 500

# Handles slash commands
def handle_event(body, headers):
    if body.get("event") == "commands":
        return handle_commands(body)
    elif body.get("event") == "actions":
        return handle_actions(body)

# Function to handle slash commands
def handle_commands(event):
    token = oauth2_connect()
    if not token:
        return

    message = f'"{event["message"]}"'
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    data = {
        "to_jid": event["payload"]["toJid"],
        "account_id": event["payload"]["accountId"],
        "header": {"text": "Vote bot"},
        "body": [
            {
                "type": "section",
                "sections": [
                    {"type": "message", "text": message},
                    {
                        "type": "actions",
                        "items": [
                            {"text": "Up Vote", "value": "up-vote", "style": "Primary"},
                            {"text": "Down Vote", "value": "down-vote", "style": "Danger"}
                        ]
                    }
                ],
                "footer": f'Vote by {event["payload"]["userName"]}'
            }
        ]
    }

    response = requests.post("https://api.zoom.us/v2/im/chat/messages", headers=headers, json=data)
    if response.status_code != 200:
        print("Error sending message:", response.json())

# Function to handle actions (button clicks)
def handle_actions(event):
    token = oauth2_connect()
    if not token:
        return

    action_text = f'{event["payload"]["userName"]} {event["payload"]["actionItem"]["text"]}d'

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    data = {
        "to_jid": event["payload"]["toJid"],
        "account_id": event["payload"]["accountId"],
        "header": {"text": f'Vote bot: {event["payload"]["original"]["body"][0]["sections"][0]["text"]}'},
        "body": {"type": "message", "text": action_text}
    }

    response = requests.post("https://api.zoom.us/v2/im/chat/messages", headers=headers, json=data)
    if response.status_code != 200:
        print("Error sending action response:", response.json())

# Support page
@app.route('/support', methods=['GET'])
def support():
    return 'Contact {{ email }} for support.'

# Privacy page
@app.route('/privacy', methods=['GET'])
def privacy():
    return 'The Vote Chatbot for Zoom does not store any user data.'

# Domain validation page
@app.route('/zoomverify/verifyzoom.html', methods=['GET'])
def zoom_verify():
    return zoom_verification_code

# Deauthorization route
@app.route('/deauthorize', methods=['POST'])
def deauthorize():
    if request.headers.get('Authorization') == verification_token:
        body = request.json
        data = {
            "client_id": body["payload"]["client_id"],
            "user_id": body["payload"]["user_id"],
            "account_id": body["payload"]["account_id"],
            "deauthorization_event_received": body["payload"],
            "compliance_completed": True
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {b64encode(f'{client_id}:{client_secret}'.encode()).decode()}"
        }

        response = requests.post("https://api.zoom.us/oauth/data/compliance", headers=headers, json=data)
        if response.status_code != 200:
            print("Error in deauthorization:", response.json())
        return '', 200
    else:
        return 'Unauthorized request to Vote Chatbot for Zoom.', 401

# Run the app
if __name__ == '__main__':
    app.run(port=int(os.getenv('PORT', 4000)), debug=True)