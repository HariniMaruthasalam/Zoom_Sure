# from flask import Flask, request, jsonify
# import time
# import os

# app = Flask(__name__)

# @app.route('/slash', methods=['POST'])
# def slash_command():
#     data = request.json
#     user_id = data['payload']['userId']
#     channel_id = data['payload']['toJid']
    
#     start_time = time.time()
#     print(f"User ID: {user_id}, Channel ID: {channel_id}")
    
#     # Mocking a function to retrieve user info and check authentication (replace with actual logic)
#     user_email = get_user_email(user_id)  # Replace with actual function to fetch user email
#     user_name = get_user_name(user_id)  # Replace with actual function to fetch user name
    
#     # Mocking prism status check
#     prism_status = get_colleague_prism_data(user_email)
    
#     # Initial message (simulating a modal-like response)
#     message = {
#         "body": {
#             "content": {
#                 "head": {
#                     "text": "SurePeople for Zoom",
#                     "style": {
#                         "bold": True
#                     }
#                 },
#                 "sections": [
#                     {
#                         "text": "_Critical insights. Effective teamwork. Peak performance._"
#                     },
#                     {
#                         "text": "⏳ Please wait while we retrieve your details. This may take a few seconds."
#                     }
#                 ]
#             }
#         },
#         "channel": channel_id
#     }
    
#     # Send initial message to Zoom chat
#     send_zoom_chat_message(channel_id, message)

#     # Simulating further actions based on user info
#     if not prism_status['completed']:
#         message['body']['content']['sections'].append({
#             "text": "⚠️ It looks like you haven’t completed the Prism yet. Please complete your registration to access SureTools."
#         })
#         send_zoom_chat_message(channel_id, message)
#     else:
#         # Further message if everything is valid
#         message['body']['content']['sections'].append({
#             "text": f"Welcome {user_name}! Your Prism is complete. You can now use SureTools for teamwork enhancement."
#         })
#         send_zoom_chat_message(channel_id, message)
    
#     print(f"Process completed in {time.time() - start_time} seconds")
    
#     return jsonify({"message": "Success"}), 200


# # Mocking helper functions (Replace with actual implementations)
# def get_user_email(user_id):
#     return "user@example.com"  # Mocked email for testing

# def get_user_name(user_id):
#     return "John Doe"  # Mocked user name

# def get_colleague_prism_data(email):
#     # Simulate fetching prism data
#     return {"completed": True}

# def send_zoom_chat_message(channel_id, message):
#     # Use Zoom's Chat API to send a message (use actual API calls)
#     print(f"Sending message to Zoom chat (Channel: {channel_id}) - {message}")
#     # Implement Zoom API call here

# if __name__ == '__main__':
#     app.run(debug=True)


# from fastapi import FastAPI, Request, HTTPException
# from pydantic import BaseModel
# from typing import Dict
# import os

# app = FastAPI()

# class SlashCommandPayload(BaseModel):
#     user_id: str
#     channel_id: str
#     command: str
#     text: str
#     trigger_id: str

# @app.post("/zoom/slash_command")
# async def handle_slash_command(payload: SlashCommandPayload):
#     try:
#         # Extract necessary details from the slash command payload
#         command_text = payload.text
#         user_id = payload.user_id
#         trigger_id = payload.trigger_id
        
#         # Build the response view (this would be the small dashboard displayed in Zoom)
#         dashboard_view = {
#             "type": "modal",
#             "callback_id": "surepeople_welcome_view",
#             "title": {
#                 "type": "plain_text",
#                 "text": "SurePeople Dashboard"
#             },
#             "blocks": [
#                 {
#                     "type": "section",
#                     "text": {
#                         "type": "mrkdwn",
#                         "text": "Welcome to SurePeople!"
#                     }
#                 },
#                 {
#                     "type": "divider"
#                 },
#                 {
#                     "type": "section",
#                     "text": {
#                         "type": "mrkdwn",
#                         "text": "*This is your dashboard view in Zoom Team Chat.*"
#                     }
#                 }
#             ]
#         }

#         # Response to send back to Zoom with the view
#         response_data = {
#             "trigger_id": trigger_id,
#             "view": dashboard_view
#         }

#         return response_data

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import Dict, Optional
import hmac
import hashlib
import json
import requests
from datetime import datetime, timedelta

app = FastAPI()
security = HTTPBasic()

# Configuration - Replace these with your actual credentials from Zoom Marketplace
ZOOM_CLIENT_ID = "tag_5FgtT9K47SvSYJBNNA"
ZOOM_CLIENT_SECRET = "ZZK6dzdjg088HMuRbbSltOiaRr7zjjDD"
ZOOM_BOT_JID = "v1irjvn0tltu2vla3bkjyfcw@xmpp.zoom.us"  # Found in your Zoom App's Bot configuration
ZOOM_VERIFICATION_TOKEN = "6Ti0QEupQVmGLBjCHl5-Og"  # Found in your Zoom App's Features -> Bot configuration

# Store for access tokens (In production, use a proper database)
token_store = {
    "access_token": None,
    "expires_at": None
}

class SlashCommandPayload(BaseModel):
    cmd: str
    uid: str
    channel_id: str
    enterprise_id: str
    team_id: str
    user_name: str
    command: str
    text: str
    response_url: str
    trigger_id: str
    token: str

async def verify_zoom_request(
    request: Request,
    x_zoom_signature: Optional[str] = Header(None),
    timestamp: Optional[str] = Header(None)
):
    """Verify that the request is coming from Zoom"""
    if not x_zoom_signature or not timestamp:
        raise HTTPException(status_code=401, detail="Missing Zoom verification headers")
    
    # Reconstruct the message
    body = await request.body()
    message = f"v0:{timestamp}:{body.decode()}"
    
    # Create hash
    hash_object = hmac.new(
        ZOOM_VERIFICATION_TOKEN.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    )
    expected_signature = f"v0={hash_object.hexdigest()}"
    
    if not hmac.compare_digest(x_zoom_signature, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

async def get_zoom_access_token():
    """Get or refresh Zoom access token"""
    global token_store
    
    now = datetime.now()
    
    # Check if we need to get a new token
    if (not token_store["access_token"] or 
        not token_store["expires_at"] or 
        now >= token_store["expires_at"]):
        
        auth_url = "https://zoom.us/oauth/token"
        auth_headers = {
            "Authorization": f"Basic {ZOOM_CLIENT_ID}:{ZOOM_CLIENT_SECRET}"
        }
        data = {
            "grant_type": "client_credentials",
            "account_id": ZOOM_CLIENT_ID
        }
        
        response = requests.post(auth_url, headers=auth_headers, data=data)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to get Zoom access token")
        
        token_data = response.json()
        token_store["access_token"] = token_data["access_token"]
        token_store["expires_at"] = now + timedelta(seconds=token_data["expires_in"])
    
    return token_store["access_token"]

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

@app.get("/")
async def home():
    return {"message": "Welcome to the SurePeople Dashboard"}

@app.post("/zoom/slash_command")
async def handle_slash_command(
    request: Request,
    payload: SlashCommandPayload,
    token: str = Depends(get_zoom_access_token)
):
    # Verify the request is from Zoom
    await verify_zoom_request(request)
    
    try:
        # Check if the verification token matches
        if payload.token != ZOOM_VERIFICATION_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid verification token")
        
        # Handle different commands
        if payload.command == "/suredev":
            dashboard_view = {
                "head": {
                    "text": "SurePeople Dashboard",
                    "style": {"bold": True}
                },
                "body": [
                    {
                        "type": "message",
                        "text": "Welcome to your SurePeople Dashboard!"
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "message",
                        "text": "Use the following commands:\n/dashboard - Show this view\n/help - Show available commands"
                    }
                ]
            }
            
            # Send response to Zoom
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                payload.response_url,
                headers=headers,
                json={"response_type": "in_channel", "body": dashboard_view}
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail="Failed to send response to Zoom")
            
            return {"status": "success"}
            
        else:
            return {
                "response_type": "in_channel",
                "text": f"Unknown command: {payload.command}"
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)