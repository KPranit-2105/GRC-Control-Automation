from datetime import datetime
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class Identity(Base):
    __tablename__ = "identities"

    id = Column(String, primary_key=True, default=generate_uuid)
    canonical_email = Column(String, unique=True, index=True, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    employee_id = Column(String, unique=True, nullable=False)
    department = Column(String, nullable=False)
    job_title = Column(String, nullable=False)
    manager_email = Column(String, nullable=True)
    hr_status = Column(String, nullable=False, default="active")  # active, terminated, on_leave
    termination_date = Column(DateTime, nullable=True)
    manager_review_status = Column(String, default="COMPLETED")  # COMPLETED, PENDING, OVERDUE
    manager_review_due_date = Column(DateTime, nullable=True)

    accounts = relationship("Account", back_populates="identity", cascade="all, delete-orphan")

class Account(Base):
    __tablename__ = "accounts"

    id = Column(String, primary_key=True, default=generate_uuid)
    system_name = Column(String, nullable=False)  # aws_iam, okta, github, k8s
    native_username = Column(String, nullable=False)
    account_type = Column(String, nullable=False, default="human")  # human, service_account
    identity_id = Column(String, ForeignKey("identities.id"), nullable=True)
    owner_email = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime, nullable=True)

    identity = relationship("Identity", back_populates="accounts")
    entitlements = relationship("Entitlement", back_populates="account", cascade="all, delete-orphan")

class Entitlement(Base):
    __tablename__ = "entitlements"

    id = Column(String, primary_key=True, default=generate_uuid)
    account_id = Column(String, ForeignKey("accounts.id"), nullable=False)
    resource_name = Column(String, nullable=False)
    privilege_level = Column(String, nullable=False)  # critical_admin, admin, write, read
    granted_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    approval_ref = Column(String, nullable=True)  # JIRA ticket or approval reference
    approved_by = Column(String, nullable=True)
    last_reviewed_at = Column(DateTime, nullable=True)

    account = relationship("Account", back_populates="entitlements")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=generate_uuid)
    rule_id = Column(String, nullable=False, index=True)
    user_email = Column(String, nullable=True)
    asset = Column(String, nullable=False)
    privilege = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    detected_at = Column(DateTime, default=datetime.utcnow)
    evidence_summary = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    status = Column(String, default="OPEN")  # OPEN, EXCEPTION_APPROVED, REMEDIATED
    owner = Column(String, nullable=False)
    due_date = Column(DateTime, nullable=False)

    exceptions = relationship("ExceptionRecord", back_populates="finding", cascade="all, delete-orphan")

class ExceptionRecord(Base):
    __tablename__ = "exceptions"

    id = Column(String, primary_key=True, default=generate_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    business_justification = Column(Text, nullable=False)
    approved_by = Column(String, nullable=False)
    approved_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String, default="ACTIVE")  # ACTIVE, EXPIRED, REVOKED

    finding = relationship("Finding", back_populates="exceptions")

class AuditEvidence(Base):
    __tablename__ = "audit_evidence"

    id = Column(String, primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow)
    rule_id = Column(String, nullable=False)
    input_source = Column(String, nullable=False)
    finding_id = Column(String, nullable=False)
    decision = Column(String, nullable=False)
    remediation_action = Column(Text, nullable=False)
    status = Column(String, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    evidence_payload = Column(Text, nullable=False)  # JSON representation
