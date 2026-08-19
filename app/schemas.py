from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, ConfigDict

class FindingBase(BaseModel):
    rule_id: str
    user_email: Optional[str] = None
    asset: str
    privilege: str
    severity: str
    evidence_summary: str
    recommended_action: str
    status: str
    owner: str
    due_date: datetime

class FindingOut(FindingBase):
    id: str
    detected_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ExceptionCreate(BaseModel):
    finding_id: str
    business_justification: str
    approved_by: str
    duration_days: int = 30

class ExceptionOut(BaseModel):
    id: str
    finding_id: str
    business_justification: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    status: str
    model_config = ConfigDict(from_attributes=True)

class AuditEvidenceOut(BaseModel):
    id: str
    timestamp: datetime
    rule_id: str
    input_source: str
    finding_id: str
    decision: str
    remediation_action: str
    status: str
    sha256_hash: str
    evidence_payload: str
    model_config = ConfigDict(from_attributes=True)

class ScanSummary(BaseModel):
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    rule_breakdown: Dict[str, int]
    scan_timestamp: datetime
