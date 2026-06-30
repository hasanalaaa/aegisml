from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
import os
import string
import random
import resend
from database import get_db
from auth.models import User
from auth.router import get_current_user
from growth.models import ReferralCode, NewsletterSubscriber

router = APIRouter()

resend.api_key = os.getenv("RESEND_API_KEY")

class SubscribeRequest(BaseModel):
    email: str

def generate_referral_code() -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

@router.post("/referral/create")
async def create_referral_code(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(ReferralCode).where(ReferralCode.user_id == str(current_user.id)))
    existing = result.scalar_one_or_none()
    
    if existing:
        return {
            "code": existing.code,
            "referral_url": f"https://aegisml.vercel.app?ref={existing.code}"
        }
    
    code = generate_referral_code()
    while True:
        check = await db.execute(select(ReferralCode).where(ReferralCode.code == code))
        if not check.scalar_one_or_none():
            break
        code = generate_referral_code()
        
    new_code = ReferralCode(user_id=str(current_user.id), code=code)
    db.add(new_code)
    await db.commit()
    await db.refresh(new_code)
    
    return {
        "code": new_code.code,
        "referral_url": f"https://aegisml.vercel.app?ref={new_code.code}"
    }

@router.get("/referral/stats")
async def get_referral_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(ReferralCode).where(ReferralCode.user_id == str(current_user.id)))
    existing = result.scalar_one_or_none()
    
    if not existing:
        return {"code": None, "referred_count": 0, "reward_status": "none"}
        
    return {
        "code": existing.code,
        "referred_count": existing.referred_count,
        "reward_status": "active"
    }

@router.post("/newsletter/subscribe")
async def subscribe_newsletter(
    req: SubscribeRequest,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(NewsletterSubscriber).where(NewsletterSubscriber.email == req.email))
    existing = result.scalar_one_or_none()
    
    if existing:
        return {"status": "success", "message": "Already subscribed"}
        
    subscriber = NewsletterSubscriber(email=req.email)
    db.add(subscriber)
    await db.commit()
    
    if resend.api_key:
        try:
            resend.Emails.send({
                "from": os.getenv("RESEND_FROM_EMAIL", "noreply@aegisml.com"),
                "to": req.email,
                "subject": "Welcome to AegisML Newsletter",
                "html": "<p>Thank you for subscribing to AegisML updates. We will keep you posted on the latest AI security news.</p>"
            })
        except Exception as e:
            import logging
            logging.error(f"Failed to send email via resend: {e}")
            
    return {"status": "success", "message": "Subscribed successfully"}
