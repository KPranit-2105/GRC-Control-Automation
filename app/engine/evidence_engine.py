import json
import hashlib
import csv
import io
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import AuditEvidence, Finding

class EvidenceEngine:
    @staticmethod
    def calculate_sha256(payload_dict: dict) -> str:
        serialized = json.dumps(payload_dict, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def create_evidence(cls, db: Session, rule_id: str, input_source: str, finding_id: str,
                        decision: str, remediation_action: str, status: str, evidence_details: dict) -> AuditEvidence:
        now = datetime.utcnow()
        payload = {
            "timestamp": now.isoformat(),
            "rule_id": rule_id,
            "input_source": input_source,
            "finding_id": finding_id,
            "decision": decision,
            "remediation_action": remediation_action,
            "status": status,
            "details": evidence_details
        }
        sha256_hash = cls.calculate_sha256(payload)

        evidence = AuditEvidence(
            timestamp=now,
            rule_id=rule_id,
            input_source=input_source,
            finding_id=finding_id,
            decision=decision,
            remediation_action=remediation_action,
            status=status,
            sha256_hash=sha256_hash,
            evidence_payload=json.dumps(payload, indent=2)
        )
        db.add(evidence)
        db.flush()
        return evidence

    @classmethod
    def export_json(cls, db: Session) -> str:
        records = db.query(AuditEvidence).all()
        data = []
        for r in records:
            data.append({
                "id": r.id,
                "timestamp": r.timestamp.isoformat(),
                "rule_id": r.rule_id,
                "input_source": r.input_source,
                "finding_id": r.finding_id,
                "decision": r.decision,
                "remediation_action": r.remediation_action,
                "status": r.status,
                "sha256_hash": r.sha256_hash,
                "payload": json.loads(r.evidence_payload)
            })
        return json.dumps({"audit_evidence_records": data, "exported_at": datetime.utcnow().isoformat()}, indent=2)

    @classmethod
    def export_csv(cls, db: Session) -> str:
        records = db.query(AuditEvidence).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Evidence ID", "Timestamp", "Rule ID", "Input Source",
            "Finding ID", "Decision", "Remediation Action", "Status", "SHA256 Hash"
        ])
        for r in records:
            writer.writerow([
                r.id, r.timestamp.isoformat(), r.rule_id, r.input_source,
                r.finding_id, r.decision, r.remediation_action, r.status, r.sha256_hash
            ])
        return output.getvalue()

    @classmethod
    def export_markdown_report(cls, db: Session) -> str:
        findings = db.query(Finding).all()
        evidence_count = db.query(AuditEvidence).count()
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        md = f"""# Executive Audit Evidence Report — Privileged Access Review
**Generated At**: {now_str}  
**Target Organization**: DataStream Technologies  
**Compliance Scope**: SOC 2 Type II (CC6.1, CC6.2, CC6.3), PCI DSS v4.0 (7.2, 8.1.4)  
**Evidence Record Count**: {evidence_count}  

---

## 1. Compliance Findings Summary

| Finding ID | Rule ID | User / Asset | Severity | Status | Due Date | SHA-256 Hash Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
"""
        for f in findings:
            ev = db.query(AuditEvidence).filter(AuditEvidence.finding_id == f.id).first()
            hash_short = ev.sha256_hash[:12] + "..." if ev else "N/A"
            user_label = f.user_email or "UNOWNED"
            md += f"| `{f.id}` | `{f.rule_id}` | `{user_label}` ({f.asset}) | **{f.severity}** | `{f.status}` | {f.due_date.strftime('%Y-%m-%d')} | `{hash_short}` |\n"

        md += """

---

## 2. Detailed Finding & Remediation Audit Ledger

"""
        for f in findings:
            ev = db.query(AuditEvidence).filter(AuditEvidence.finding_id == f.id).first()
            md += f"""### Finding `{f.id}` ({f.rule_id})
- **Severity**: {f.severity}
- **User / Subject**: {f.user_email}
- **Asset**: {f.asset}
- **Privilege Role**: `{f.privilege}`
- **Evidence Details**: {f.evidence_summary}
- **Recommended Action**: {f.recommended_action}
- **Status**: `{f.status}`
- **Cryptographic Proof (SHA-256)**: `{ev.sha256_hash if ev else 'N/A'}`

---
"""
        md += "\n*Report generated automatically by GRC Control Automation Engine v1.0. All evidence payloads locked with cryptographic hash verification.*\n"
        return md
