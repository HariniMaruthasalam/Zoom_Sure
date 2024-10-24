# from fastapi import FastAPI, Request, HTTPException
# from fastapi.responses import RedirectResponse
# from pydantic import BaseModel
# import os
# import requests
# from dotenv import load_dotenv
# import uvicorn
# import logging

# load_dotenv()

# # Set up logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # Zoom OAuth credentials
# ZOOM_CLIENT_ID = os.getenv('ZOOM_CLIENT_ID')
# ZOOM_CLIENT_SECRET = os.getenv('ZOOM_CLIENT_SECRET')

# # Update this with your ngrok URL
# REDIRECT_URI = "https://2804-2409-40f4-2042-5d10-a07a-2ff2-7500-a6c0.ngrok-free.app/zoom/oauth_redirect"

# app = FastAPI()

# @app.get("/zoom/install")
# async def install():
#     redirect_url = f"https://zoom.us/oauth/authorize?response_type=code&client_id={ZOOM_CLIENT_ID}&redirect_uri={REDIRECT_URI}"
#     return RedirectResponse(url=redirect_url)

# @app.get("/zoom/oauth_redirect")
# async def oauth_redirect(request: Request):
#     logger.info("Received request to /zoom/oauth_redirect")
#     try:
#         code = request.query_params.get("code")
#         logger.info(f"Received code: {code}")
        
#         if not code:
#             logger.error("Missing 'code' parameter")
#             raise HTTPException(status_code=400, detail="Error: Missing 'code' parameter")

#         response = requests.post("https://zoom.us/oauth/token", data={
#             "grant_type": "authorization_code",
#             "client_id": ZOOM_CLIENT_ID,
#             "client_secret": ZOOM_CLIENT_SECRET,
#             "code": code,
#             "redirect_uri": REDIRECT_URI
#         })

#         zoom_data = response.json()
#         logger.info(f"Zoom API response: {zoom_data}")
        
#         if "access_token" in zoom_data:
#             access_token = zoom_data["access_token"]
#             user_id = zoom_data["user_id"]

#             add_app_response = requests.post(
#                 "https://api.zoom.us/v2/users/me/chat_apps",
#                 headers={
#                     "Authorization": f"Bearer {access_token}",
#                     "Content-Type": "application/json"
#                 },
#                 json={
#                     "app_id": ZOOM_CLIENT_ID,
#                     "permissions": ["enable_user_managed_app", "allow_shared_access"]
#                 }
#             )

#             if add_app_response.status_code == 201:
#                 logger.info("Successfully added app to user's dashboard")
#                 return RedirectResponse(url="/success")  # Redirect to a local success route
#             else:
#                 logger.error(f"Failed to add app to user's dashboard: {add_app_response.text}")
#                 return {"error": "Failed to add app to user's dashboard"}
#         else:
#             logger.error("Failed to obtain access token")
#             return {"error": "Failed to obtain access token"}
    
#     except Exception as e:
#         logger.error(f"Error in oauth_redirect: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# @app.get("/success")
# async def success():
#     return {"message": "OAuth flow completed successfully"}

# class OAuthTokenResponse(BaseModel):
#     oauth_token: str

# @app.get("/oauth_token/{user_id}", response_model=OAuthTokenResponse)
# async def get_oauth_token(user_id: str):
#     return {"oauth_token": "None"}

# if __name__ == "__main__":
#     uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)


# from fastapi import FastAPI, Request, HTTPException
# from fastapi.responses import RedirectResponse
# from pydantic import BaseModel
# import os
# import requests
# from dotenv import load_dotenv
# import uvicorn
# import logging

# # Set up logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # Load environment variables
# load_dotenv()

# # Zoom OAuth credentials
# ZOOM_CLIENT_ID = os.getenv('ZOOM_CLIENT_ID')
# ZOOM_CLIENT_SECRET = os.getenv('ZOOM_CLIENT_SECRET')

# # Update this with your ngrok URL
# REDIRECT_URI = "https://e17a-45-127-108-190.ngrok-free.app/zoom/oauth_redirect"

# app = FastAPI()

# # Middleware to add OWASP security headers
# @app.middleware("http")
# async def add_security_headers(request: Request, call_next):
#     response = await call_next(request)
    
#     # Add OWASP recommended headers
#     response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
#     response.headers['X-Content-Type-Options'] = 'nosniff'
#     response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
#     response.headers['Referrer-Policy'] = 'no-referrer'
    
#     return response

# @app.get("/zoom/install")
# async def install():
#     redirect_url = f"https://zoom.us/oauth/authorize?response_type=code&client_id={ZOOM_CLIENT_ID}&redirect_uri={REDIRECT_URI}"
#     return RedirectResponse(url=redirect_url)

# @app.get("/zoom/oauth_redirect")
# async def oauth_redirect(request: Request):
#     logger.info("Received request to /zoom/oauth_redirect")
#     try:
#         code = request.query_params.get("code")
#         logger.info(f"Received code: {code}")
        
#         if not code:
#             logger.error("Missing 'code' parameter")
#             raise HTTPException(status_code=400, detail="Error: Missing 'code' parameter")

#         # Exchange code for access_token
#         response = requests.post("https://zoom.us/oauth/token", data={
#             "grant_type": "authorization_code",
#             "client_id": ZOOM_CLIENT_ID,
#             "client_secret": ZOOM_CLIENT_SECRET,
#             "code": code,
#             "redirect_uri": REDIRECT_URI
#         })

#         zoom_data = response.json()
#         logger.info(f"Zoom API response: {zoom_data}")
        
#         if "access_token" in zoom_data:
#             access_token = zoom_data["access_token"]
#             logger.info("Access token obtained successfully")

#             # Optionally, you can save the access_token in your database for future API requests

#             return RedirectResponse(url="/success")
#         else:
#             logger.error("Failed to obtain access token")
#             return {"error": "Failed to obtain access token", "details": zoom_data}
    
#     except Exception as e:
#         logger.error(f"Error in oauth_redirect: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# if __name__ == "__main__":
#     uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import os
import requests
from dotenv import load_dotenv
import uvicorn
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Zoom OAuth credentials
ZOOM_CLIENT_ID = os.getenv('ZOOM_CLIENT_ID')
ZOOM_CLIENT_SECRET = os.getenv('ZOOM_CLIENT_SECRET')

# Update this with your ngrok URL
REDIRECT_URI = "https://0ac7-103-130-89-21.ngrok-free.app/zoom/oauth_redirect"

app = FastAPI()

# Middleware to add OWASP security headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Add OWASP recommended headers
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    return response

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

        # Exchange code for access_token
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
            user_id = zoom_data.get("user_id")  # Get user_id if available
            logger.info("Access token obtained successfully")

            # Optionally, save user_id and access_token in your database
            # add_new_user(user_id, access_token)

            return RedirectResponse(url="/success")
        else:
            logger.error("Failed to obtain access token")
            return {"error": "Failed to obtain access token", "details": zoom_data}
    
    except Exception as e:
        logger.error(f"Error in oauth_redirect: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# Define the user invitation request model
class UserInviteRequest(BaseModel):
    email: str
    first_name: str
    last_name: str

@app.post("/zoom/invite_user")
async def invite_user(user: UserInviteRequest):
    try:
        access_token = os.getenv('ZOOM_ACCESS_TOKEN') 

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        user_data = {
            "action": "add",  # Specify the action to add a user
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
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
