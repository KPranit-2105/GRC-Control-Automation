from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Finding, ExceptionRecord, AuditEvidence
from app.schemas import FindingOut, ExceptionCreate, ExceptionOut, AuditEvidenceOut, ScanSummary
from app.engine.rules_engine import RulesEngine
from app.engine.evidence_engine import EvidenceEngine

router = APIRouter(prefix="/api/v1", tags=["GRC Control Automation Engine"])

@router.post("/scan", response_model=ScanSummary)
def run_compliance_scan(db: Session = Depends(get_db)):
    """
    Trigger the automated rule engine to evaluate all access control policies.
    """
    engine = RulesEngine()
    findings = engine.run_all_rules(db)

    rule_breakdown = {}
    critical = high = medium = low = 0

    for f in findings:
        rule_breakdown[f.rule_id] = rule_breakdown.get(f.rule_id, 0) + 1
        if f.severity == "CRITICAL":
            critical += 1
        elif f.severity == "HIGH":
            high += 1
        elif f.severity == "MEDIUM":
            medium += 1
        else:
            low += 1

    return ScanSummary(
        total_findings=len(findings),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        rule_breakdown=rule_breakdown,
        scan_timestamp=datetime.utcnow()
    )

@router.get("/findings", response_model=List[FindingOut])
def list_findings(
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    status: Optional[str] = Query(None, description="Filter by status (OPEN, EXCEPTION_APPROVED, REMEDIATED)"),
    rule_id: Optional[str] = Query(None, description="Filter by Rule ID (e.g., RULE-001)"),
    db: Session = Depends(get_db)
):
    """
    Retrieve compliance findings with optional filtering.
    """
    query = db.query(Finding)
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if status:
        query = query.filter(Finding.status == status.upper())
    if rule_id:
        query = query.filter(Finding.rule_id == rule_id.upper())
    return query.order_by(Finding.detected_at.desc()).all()

@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """
    Retrieve details for a specific finding.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.post("/exceptions", response_model=ExceptionOut)
def request_exception(payload: ExceptionCreate, db: Session = Depends(get_db)):
    """
    Submit a formal risk acceptance exception for a finding.
    """
    finding = db.query(Finding).filter(Finding.id == payload.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    now = datetime.utcnow()
    expires_at = now + timedelta(days=payload.duration_days)

    exc = ExceptionRecord(
        finding_id=payload.finding_id,
        business_justification=payload.business_justification,
        approved_by=payload.approved_by,
        approved_at=now,
        expires_at=expires_at,
        status="ACTIVE"
    )
    db.add(exc)
    
    # Update finding status
    finding.status = "EXCEPTION_APPROVED"
    db.commit()
    db.refresh(exc)

    # Generate audit evidence of human risk acceptance decision
    EvidenceEngine.create_evidence(
        db=db,
        rule_id=finding.rule_id,
        input_source="GRC_Exception_Portal",
        finding_id=finding.id,
        decision="RISK_ACCEPTED",
        remediation_action=f"Human risk acceptance approved by {payload.approved_by} until {expires_at.isoformat()}",
        status="EXCEPTION_APPROVED",
        evidence_details={
            "finding_id": finding.id,
            "approved_by": payload.approved_by,
            "business_justification": payload.business_justification,
            "expires_at": expires_at.isoformat()
        }
    )

    return exc

@router.get("/exceptions", response_model=List[ExceptionOut])
def list_exceptions(db: Session = Depends(get_db)):
    """
    List all recorded risk exceptions.
    """
    return db.query(ExceptionRecord).order_by(ExceptionRecord.approved_at.desc()).all()

@router.get("/evidence", response_model=List[AuditEvidenceOut])
def list_evidence(db: Session = Depends(get_db)):
    """
    List cryptographic audit evidence ledger records.
    """
    return db.query(AuditEvidence).order_by(AuditEvidence.timestamp.desc()).all()

@router.get("/evidence/export")
def export_evidence(format: str = Query("json", description="Export format: json, csv, or markdown"), db: Session = Depends(get_db)):
    """
    Export audit-ready evidence packages in JSON, CSV, or Markdown format.
    """
    fmt = format.lower()
    if fmt == "csv":
        content = EvidenceEngine.export_csv(db)
        return Response(content=content, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit_evidence.csv"})
    elif fmt == "markdown" or fmt == "md":
        content = EvidenceEngine.export_markdown_report(db)
        return Response(content=content, media_type="text/markdown", headers={"Content-Disposition": "attachment; filename=audit_evidence_report.md"})
    else:
        content = EvidenceEngine.export_json(db)
        return Response(content=content, media_type="application/json", headers={"Content-Disposition": "attachment; filename=audit_evidence.json"})

@router.get("/metrics")
def get_compliance_metrics(db: Session = Depends(get_db)):
    """
    Get executive GRC metrics and manual-vs-automated savings telemetry.
    """
    total_findings = db.query(Finding).count()
    open_findings = db.query(Finding).filter(Finding.status == "OPEN").count()
    exceptions = db.query(Finding).filter(Finding.status == "EXCEPTION_APPROVED").count()
    remediated = db.query(Finding).filter(Finding.status == "REMEDIATED").count()
    evidence_count = db.query(AuditEvidence).count()

    return {
        "metrics": {
            "total_findings_detected": total_findings,
            "open_findings": open_findings,
            "active_exceptions": exceptions,
            "remediated_findings": remediated,
            "evidence_coverage_pct": 100.0,
            "mean_time_to_detect_minutes": 2.5,
            "manual_hours_saved_per_quarter": 62.5,
            "evidence_ledger_size": evidence_count
        },
        "disclaimer": "Fictional portfolio prototype demonstration metrics."
    }
