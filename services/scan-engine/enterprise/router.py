from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import re
import uuid

from database import get_db
from auth.models import User
from auth.utils import get_current_user
from .models import AuditLog, CustomThreatRule, OrgMember

router = APIRouter(tags=["Enterprise"])


# --- Real Security Dependency ------------------------------------------
# Real JWT-backed authentication via get_current_user, enforcing the
# required role. 'enterprise' plan holders and explicit 'admin' role users
# are treated as org admins for their own org space.
def require_role(required_role: str):
    async def role_dependency(
        current_user: Optional[User] = Depends(get_current_user),
    ) -> User:
        if current_user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        is_admin = current_user.role == "admin" or current_user.plan == "enterprise"
        if required_role == "admin" and not is_admin:
            raise HTTPException(status_code=403, detail="Admin or Enterprise plan required")
        return current_user
    return role_dependency


async def _write_audit_log(db: AsyncSession, user: User, action: str,
                           resource: Optional[str] = None, ip: Optional[str] = None):
    log = AuditLog(
        org_id=user.id,  # single-tenant-per-user: the user's id is their org id
        user_id=user.id,
        action=action,
        resource=resource,
        ip_address=ip,
    )
    db.add(log)
    # caller is responsible for commit


# --- Schemas ---
class AuditLogResponse(BaseModel):
    id: int
    action: str
    user_id: uuid.UUID
    resource: Optional[str]
    ip_address: Optional[str]
    created_at: datetime

class ThreatRuleCreate(BaseModel):
    name: str
    regex_pattern: str
    severity: str
    description: Optional[str] = None

class ThreatRuleResponse(BaseModel):
    id: int
    name: str
    regex_pattern: str
    severity: str
    description: Optional[str]
    is_active: bool
    created_at: datetime

class MemberInvite(BaseModel):
    email: str
    role: str

class MemberResponse(BaseModel):
    id: int
    email: str
    role: str
    status: str
    joined_at: datetime


# --- Endpoints ---

@router.get("/audit-logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.org_id == user.id)
        .order_by(desc(AuditLog.created_at))
        .offset(skip)
        .limit(limit)
    )
    logs = result.scalars().all()
    return [
        AuditLogResponse(
            id=l.id, action=l.action, user_id=l.user_id,
            resource=l.resource, ip_address=l.ip_address, created_at=l.created_at,
        )
        for l in logs
    ]


def _validate_regex(pattern: str):
    try:
        re.compile(pattern)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")


@router.post("/threat-rules", response_model=ThreatRuleResponse)
async def create_threat_rule(
    rule: ThreatRuleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    _validate_regex(rule.regex_pattern)
    if rule.severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="severity must be one of: low, medium, high, critical")

    new_rule = CustomThreatRule(
        org_id=user.id,
        name=rule.name,
        regex_pattern=rule.regex_pattern,
        severity=rule.severity,
        description=rule.description,
        is_active=True,
    )
    db.add(new_rule)
    await _write_audit_log(db, user, "rule.created", resource=rule.name,
                           ip=request.client.host if request.client else None)
    await db.commit()
    await db.refresh(new_rule)
    return ThreatRuleResponse(
        id=new_rule.id, name=new_rule.name, regex_pattern=new_rule.regex_pattern,
        severity=new_rule.severity, description=new_rule.description,
        is_active=new_rule.is_active, created_at=new_rule.created_at,
    )


@router.get("/threat-rules", response_model=List[ThreatRuleResponse])
async def list_threat_rules(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(CustomThreatRule)
        .where(CustomThreatRule.org_id == user.id)
        .order_by(desc(CustomThreatRule.created_at))
    )
    rules = result.scalars().all()
    return [
        ThreatRuleResponse(
            id=r.id, name=r.name, regex_pattern=r.regex_pattern, severity=r.severity,
            description=r.description, is_active=r.is_active, created_at=r.created_at,
        )
        for r in rules
    ]


@router.put("/threat-rules/{rule_id}", response_model=ThreatRuleResponse)
async def update_threat_rule(
    rule_id: int,
    rule: ThreatRuleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    _validate_regex(rule.regex_pattern)
    result = await db.execute(
        select(CustomThreatRule).where(
            CustomThreatRule.id == rule_id,
            CustomThreatRule.org_id == user.id,
        )
    )
    existing = result.scalar_one_or_none()
    if not existing:
        raise HTTPException(status_code=404, detail="Threat rule not found")

    existing.name = rule.name
    existing.regex_pattern = rule.regex_pattern
    existing.severity = rule.severity
    existing.description = rule.description
    await db.commit()
    await db.refresh(existing)
    return ThreatRuleResponse(
        id=existing.id, name=existing.name, regex_pattern=existing.regex_pattern,
        severity=existing.severity, description=existing.description,
        is_active=existing.is_active, created_at=existing.created_at,
    )


@router.delete("/threat-rules/{rule_id}")
async def delete_threat_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(CustomThreatRule).where(
            CustomThreatRule.id == rule_id,
            CustomThreatRule.org_id == user.id,
        )
    )
    existing = result.scalar_one_or_none()
    if not existing:
        raise HTTPException(status_code=404, detail="Threat rule not found")
    await db.delete(existing)
    await db.commit()
    return {"status": "success", "deleted_rule_id": rule_id}


@router.get("/members", response_model=List[MemberResponse])
async def list_members(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(OrgMember)
        .where(OrgMember.org_id == user.id)
        .order_by(desc(OrgMember.joined_at))
    )
    members = result.scalars().all()

    # Ensure the org owner always appears as an active admin, even before any
    # explicit OrgMember row exists for them.
    has_owner = any(m.email == user.email for m in members)
    response = [
        MemberResponse(id=m.id, email=m.email, role=m.role, status=m.status, joined_at=m.joined_at)
        for m in members
    ]
    if not has_owner:
        response.insert(0, MemberResponse(
            id=0, email=user.email, role="admin", status="active", joined_at=user.created_at,
        ))
    return response


@router.post("/members/invite", response_model=MemberResponse)
async def invite_member(
    invite: MemberInvite,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    if invite.role not in ("admin", "editor", "viewer"):
        raise HTTPException(status_code=400, detail="role must be one of: admin, editor, viewer")

    # Prevent duplicate invites for the same email within an org
    existing = await db.execute(
        select(OrgMember).where(
            OrgMember.org_id == user.id,
            OrgMember.email == invite.email,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="This email has already been invited")

    member = OrgMember(
        org_id=user.id,
        user_id=None,  # set when the invitee accepts
        email=invite.email,
        role=invite.role,
        status="pending",
    )
    db.add(member)
    await _write_audit_log(db, user, "member.invited", resource=invite.email,
                           ip=request.client.host if request.client else None)
    await db.commit()
    await db.refresh(member)
    return MemberResponse(
        id=member.id, email=member.email, role=member.role,
        status=member.status, joined_at=member.joined_at,
    )


@router.delete("/members/{member_id}")
async def delete_member(
    member_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(OrgMember).where(
            OrgMember.id == member_id,
            OrgMember.org_id == user.id,
        )
    )
    existing = result.scalar_one_or_none()
    if not existing:
        raise HTTPException(status_code=404, detail="Member not found")
    await db.delete(existing)
    await db.commit()
    return {"status": "success", "deleted_member_id": member_id}
