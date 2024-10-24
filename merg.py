from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Dict, Optional
import hmac
import hashlib
import json
import requests
import os
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
import requests
import logging
from typing import Optional
from pydantic import BaseModel
import json

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = FastAPI()
security = HTTPBasic()

# Configuration
ZOOM_CLIENT_ID = os.getenv('ZOOM_CLIENT_ID', "tag_5FgtT9K47SvSYJBNNA")
ZOOM_CLIENT_SECRET = os.getenv('ZOOM_CLIENT_SECRET', "ZZK6dzdjg088HMuRbbSltOiaRr7zjjDD")
ZOOM_BOT_JID = os.getenv('ZOOM_BOT_JID', "v1irjvn0tltu2vla3bkjyfcw@xmpp.zoom.us")
ZOOM_VERIFICATION_TOKEN = os.getenv('ZOOM_VERIFICATION_TOKEN', "6Ti0QEupQVmGLBjCHl5-Og")
REDIRECT_URI = os.getenv('REDIRECT_URI', "https://5326-2409-40f4-204e-bc54-adde-e19e-5805-d21.ngrok-free.app/zoom/oauth_redirect")

# Store for access tokens (In production, use a proper database)
token_store = {
    "access_token": None,
    "expires_at": None
}

# Pydantic Models
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

class UserInviteRequest(BaseModel):
    email: str
    first_name: str
    last_name: str

# Security Functions
async def verify_zoom_request(
    request: Request,
    x_zoom_signature: Optional[str] = Header(None),
    timestamp: Optional[str] = Header(None)
):
    """Verify that the request is coming from Zoom"""
    if not x_zoom_signature or not timestamp:
        raise HTTPException(status_code=401, detail="Missing Zoom verification headers")
    
    body = await request.body()
    message = f"v0:{timestamp}:{body.decode()}"
    
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

# Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# Routes
@app.get("/")
async def home():
    return {"message": "Welcome to the SurePeople Dashboard"}

@app.get("/zoom/install")
async def install():
    redirect_url = f"https://zoom.us/oauth/authorize?response_type=code&client_id={ZOOM_CLIENT_ID}&redirect_uri={REDIRECT_URI}"
    return RedirectResponse(url=redirect_url)

@app.get("/zoom/oauth_redirect")
async def oauth_redirect(request: Request):
    logger.info("Received request to /zoom/oauth_redirect")
    try:
        code = request.query_params.get("code")
        logger.info(f"Received code: {code}")
        
        if not code:
            logger.error("Missing 'code' parameter")
            raise HTTPException(status_code=400, detail="Error: Missing 'code' parameter")

        response = requests.post("https://zoom.us/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": ZOOM_CLIENT_ID,
            "client_secret": ZOOM_CLIENT_SECRET,
            "code": code,
            "redirect_uri": REDIRECT_URI
        })

        zoom_data = response.json()
        logger.info(f"Zoom API response: {zoom_data}")
        
        if "access_token" in zoom_data:
            access_token = zoom_data["access_token"]
            user_id = zoom_data.get("user_id")
            logger.info("Access token obtained successfully")
            return RedirectResponse(url="/success")
        else:
            logger.error("Failed to obtain access token")
            return {"error": "Failed to obtain access token", "details": zoom_data}
    
    except Exception as e:
        logger.error(f"Error in oauth_redirect: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.post("/zoom/slash_command")
async def handle_slash_command(
    request: Request,
    payload: SlashCommandPayload,
    token: str = Depends(get_zoom_access_token)
):
    """Handle Zoom slash commands with comprehensive error handling and logging"""
    try:
        # Log incoming request
        logger.info(f"Received slash command: {payload.command}")
        
        # Verify the request
        await verify_zoom_request(request)
        
        # Verify the token
        if payload.token != "YOUR_ZOOM_VERIFICATION_TOKEN":
            logger.warning(f"Invalid verification token received: {payload.token}")
            raise HTTPException(status_code=401, detail="Invalid verification token")
        
        if payload.command == "/suredev":
            # Log dashboard request
            logger.info("Processing /suredev dashboard command")
            
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
            
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            try:
                # Log the outgoing request
                logger.debug(f"Sending dashboard response to: {payload.response_url}")
                
                response = requests.post(
                    payload.response_url,
                    headers=headers,
                    json={"response_type": "in_channel", "body": dashboard_view},
                    timeout=10  # Add timeout
                )
                
                # Log the response
                logger.info(f"Zoom API response status: {response.status_code}")
                
                if response.status_code != 200:
                    error_msg = f"Failed to send response to Zoom: {response.text}"
                    logger.error(error_msg)
                    raise HTTPException(status_code=500, detail=error_msg)
                
                return JSONResponse(
                    content={"status": "success"},
                    status_code=200
                )
                
            except requests.exceptions.RequestException as e:
                error_msg = f"Request to Zoom API failed: {str(e)}"
                logger.error(error_msg, exc_info=True)
                raise HTTPException(status_code=500, detail=error_msg)
            
        else:
            # Log unknown command
            logger.warning(f"Unknown command received: {payload.command}")
            return JSONResponse(
                content={
                    "response_type": "in_channel",
                    "text": f"Unknown command: {payload.command}"
                },
                status_code=200
            )

    except HTTPException as he:
        # Re-raise HTTP exceptions as they're already properly formatted
        raise he
    except Exception as e:
        # Log unexpected errors
        error_msg = f"Unexpected error in slash command handler: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise HTTPException(status_code=500, detail=error_msg)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler to ensure consistent error responses"""
    error_msg = str(exc)
    logger.error(f"Global exception handler caught: {error_msg}", exc_info=True)
    
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )
    
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred. Please try again later."}
    )

@app.post("/zoom/invite_user")
async def invite_user(user: UserInviteRequest):
    try:
        access_token = await get_zoom_access_token()

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        user_data = {
            "action": "add",
            "user_info": {
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name
            }
        }

        response = requests.post(
            "https://api.zoom.us/v2/users",
            headers=headers,
            json=user_data
        )

        if response.status_code == 201:
            logger.info(f"User {user.email} invited successfully.")
            return {"message": f"User {user.email} invited successfully."}
        else:
            logger.error(f"Failed to invite user: {response.text}")
            raise HTTPException(status_code=response.status_code, detail=response.json())
    
    except Exception as e:
        logger.error(f"Error inviting user: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/success")
async def success():
    return {"message": "You have successfully connected to Zoom!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)