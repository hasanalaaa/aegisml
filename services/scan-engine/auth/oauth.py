import os
import httpx
from typing import Optional, Dict, Any

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")

async def get_github_user_info(code: str) -> Optional[Dict[str, Any]]:
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
        )
        if token_response.status_code != 200:
            return None
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            return None
            
        user_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_response.status_code != 200:
            return None
            
        user_info = user_response.json()
        
        email = user_info.get("email")
        if not email:
            email_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if email_response.status_code == 200:
                emails = email_response.json()
                primary = next((e for e in emails if e.get("primary")), None)
                if primary:
                    email = primary.get("email")
        
        if not email:
            return None
            
        return {
            "email": email,
            "username": user_info.get("login"),
            "display_name": user_info.get("name"),
            "avatar_url": user_info.get("avatar_url"),
            "provider_id": str(user_info.get("id")),
        }

async def get_google_user_info(code: str) -> Optional[Dict[str, Any]]:
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": GOOGLE_REDIRECT_URI,
            },
        )
        if token_response.status_code != 200:
            return None
            
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            return None
            
        user_response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_response.status_code != 200:
            return None
            
        user_info = user_response.json()
        email = user_info.get("email")
        if not email:
            return None

        return {
            "email": email,
            "username": email.split("@")[0],
            "display_name": user_info.get("name"),
            "avatar_url": user_info.get("picture"),
            "provider_id": str(user_info.get("id")),
        }
