from datetime import datetime, timezone

from flask_login import UserMixin

from database.db import db


def _utcnow():
    """Timezone-aware UTC timestamp helper (avoids datetime.utcnow deprecation)."""
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False,
        index=True          # Bug #14: index for fast username lookups
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=True,
        index=True          # Bug #14: index for email uniqueness checks
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="operator",
        index=True          # Bug #14: index for role-based queries
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=_utcnow     # Bug #20: use timezone-aware datetime
    )


class Detection(db.Model):

    __tablename__ = "detections"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    module_name = db.Column(
        db.String(100),
        nullable=False,
        index=True          # Bug #14: index for module filter queries
    )

    object_detected = db.Column(
        db.String(100),
        nullable=False
    )

    confidence = db.Column(
        db.Float,
        nullable=False
    )

    threat_level = db.Column(
        db.String(20),
        nullable=False,
        index=True          # Bug #14: index for threat-level queries
    )

    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=_utcnow,
        index=True          # Bug #14: index for date-range queries
    )


class Log(db.Model):

    __tablename__ = "logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    event = db.Column(
        db.Text,
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=_utcnow,    # Bug #20: use timezone-aware datetime
        index=True          # Bug #14: index for chronological log queries
    )