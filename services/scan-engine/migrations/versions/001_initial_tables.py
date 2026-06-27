"""initial_tables

Revision ID: 001_initial
Revises: None
Create Date: 2026-06-27
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── scans ────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("filename", sa.String(500), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("file_extension", sa.String(20), nullable=True),
        sa.Column("file_hash", sa.String(64), nullable=True),
        sa.Column("risk_score", sa.Float(), server_default="0.0"),
        sa.Column("risk_level", sa.String(20), server_default="'clean'"),
        sa.Column("threats", sa.JSON(), nullable=True),
        sa.Column("metadata_info", sa.JSON(), nullable=True),
        sa.Column("ai_verdict", sa.String(20), nullable=True),
        sa.Column("ai_confidence", sa.Integer(), nullable=True),
        sa.Column("ai_summary_en", sa.Text(), nullable=True),
        sa.Column("ai_summary_ar", sa.Text(), nullable=True),
        sa.Column("ai_key_risks", sa.JSON(), nullable=True),
        sa.Column("ai_recommendation_en", sa.Text(), nullable=True),
        sa.Column("ai_recommendation_ar", sa.Text(), nullable=True),
        sa.Column("source_type", sa.String(20), server_default="'upload'"),
        sa.Column("source_url", sa.String(2000), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("is_public", sa.Boolean(), server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_scans_scan_id", "scans", ["scan_id"])
    op.create_index("ix_scans_file_hash", "scans", ["file_hash"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])

    # ── threat_patterns ──────────────────────────────────────────
    op.create_table(
        "threat_patterns",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("pattern", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(50), nullable=True),
        sa.Column("description_en", sa.Text(), nullable=True),
        sa.Column("description_ar", sa.Text(), nullable=True),
        sa.Column("times_detected", sa.Integer(), server_default="0"),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("pattern"),
    )

    # ── api_keys ─────────────────────────────────────────────────
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("key_prefix", sa.String(12), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("email", sa.String(200), nullable=True),
        sa.Column("scans_used", sa.Integer(), server_default="0"),
        sa.Column("scans_limit", sa.Integer(), server_default="500"),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("last_used", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash"),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"])


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("threat_patterns")
    op.drop_table("scans")
