import os
import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from typing import Optional
import datetime
from database import AsyncSessionLocal
from sqlalchemy import select
from auth.models import User
from auth.utils import get_current_user

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_mock")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_mock")

PLANS = {
  "free":       {"scans": 100,   "price": 0},
  "pro":        {"scans": 5000,  "price": os.getenv("STRIPE_PRO_PRICE_ID", "price_pro_mock")},
  "enterprise": {"scans": -1,    "price": os.getenv("STRIPE_ENTERPRISE_PRICE_ID", "price_ent_mock")}
}

router = APIRouter(tags=["Billing"])

class CheckoutRequest(BaseModel):
    plan: str

@router.post("/checkout")
async def create_checkout_session(req: CheckoutRequest, current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if req.plan not in PLANS or req.plan == "free":
        raise HTTPException(status_code=400, detail="Invalid plan")

    price_id = PLANS[req.plan]["price"]
    
    customer_id = current_user.stripe_customer_id
    if not customer_id:
        # Create customer
        customer = stripe.Customer.create(email=current_user.email, metadata={"user_id": str(current_user.id)})
        customer_id = customer.id
        async with AsyncSessionLocal() as session:
            user = await session.get(User, current_user.id)
            if user:
                user.stripe_customer_id = customer_id
                await session.commit()

    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
    
    try:
        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{frontend_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{frontend_url}/pricing",
            metadata={"user_id": str(current_user.id), "plan": req.plan}
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/portal")
async def create_portal_session(current_user: User = Depends(get_current_user)):
    if not current_user or not current_user.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No billing history")
    
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
    try:
        session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,
            return_url=f"{frontend_url}/billing"
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/usage")
async def get_usage(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    plan = current_user.plan
    if plan not in PLANS:
        plan = "free"
        
    limit = PLANS[plan]["scans"]
    
    # next reset date is 1st of next month
    now = datetime.datetime.now()
    if now.month == 12:
        next_month = now.replace(year=now.year+1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        next_month = now.replace(month=now.month+1, day=1, hour=0, minute=0, second=0, microsecond=0)
        
    return {
        "plan": plan,
        "scans_used": current_user.scans_this_month,
        "scans_limit": limit,
        "reset_date": next_month.isoformat()
    }

@router.post("/cancel")
async def cancel_subscription(current_user: User = Depends(get_current_user)):
    if not current_user or not current_user.stripe_subscription_id:
        raise HTTPException(status_code=400, detail="No active subscription")
    
    try:
        stripe.Subscription.delete(current_user.stripe_subscription_id)
        async with AsyncSessionLocal() as session:
            user = await session.get(User, current_user.id)
            if user:
                user.plan = "free"
                user.stripe_subscription_id = None
                await session.commit()
        return {"status": "success", "message": "Subscription cancelled"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        raise HTTPException(status_code=400, detail="Missing signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {str(e)}")

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get("metadata", {}).get("user_id")
        plan = session.get("metadata", {}).get("plan")
        sub_id = session.get("subscription")
        
        if user_id and plan:
            async with AsyncSessionLocal() as db_session:
                user = await db_session.get(User, user_id)
                if user:
                    user.plan = plan
                    user.stripe_subscription_id = sub_id
                    await db_session.commit()

    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription.get("customer")
        
        if customer_id:
            async with AsyncSessionLocal() as db_session:
                result = await db_session.execute(select(User).where(User.stripe_customer_id == customer_id))
                user = result.scalar_one_or_none()
                if user:
                    user.plan = "free"
                    user.stripe_subscription_id = None
                    await db_session.commit()

    return Response(status_code=200)
