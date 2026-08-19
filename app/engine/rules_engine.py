import os
from datetime import datetime, timedelta
import yaml
from sqlalchemy.orm import Session
from app.models import Identity, Account, Entitlement, Finding, ExceptionRecord
from app.engine.evidence_engine import EvidenceEngine

class RulesEngine:
    def __init__(self, rules_dir: str = None):
        if rules_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            rules_dir = os.path.join(base_dir, "rules")
        self.rules_dir = rules_dir
        self.rules = self._load_rules()

    def _load_rules(self) -> dict:
        rules = {}
        if not os.path.exists(self.rules_dir):
            return rules
        
        for fname in sorted(os.listdir(self.rules_dir)):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                filepath = os.path.join(self.rules_dir, fname)
                with open(filepath, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "rule_id" in data:
                        rules[data["rule_id"]] = data
        return rules

    def run_all_rules(self, db: Session) -> list[Finding]:
        findings = []
        now = datetime.utcnow()

        # Execute individual rule detection handlers
        findings.extend(self._eval_rule_001(db, now))
        findings.extend(self._eval_rule_002(db, now))
        findings.extend(self._eval_rule_003(db, now))
        findings.extend(self._eval_rule_004(db, now))
        findings.extend(self._eval_rule_005(db, now))
        findings.extend(self._eval_rule_006(db, now))
        findings.extend(self._eval_rule_007(db, now))
        findings.extend(self._eval_rule_008(db, now))

        db.commit()
        return findings

    def _upsert_finding(self, db: Session, rule_id: str, user_email: str, asset: str, privilege: str,
                        evidence_summary: str, input_source: str, now: datetime) -> Finding:
        rule_meta = self.rules.get(rule_id, {
            "severity": "HIGH",
            "recommended_action": "Review access privilege.",
            "due_days": 3,
            "owner": "SecOps"
        })

        # Check for pre-existing finding with same rule, user_email, and asset
        existing = db.query(Finding).filter(
            Finding.rule_id == rule_id,
            Finding.user_email == user_email,
            Finding.asset == asset,
            Finding.privilege == privilege
        ).first()

        due_date = now + timedelta(days=rule_meta.get("due_days", 3))

        if existing:
            existing.detected_at = now
            existing.evidence_summary = evidence_summary
            finding = existing
        else:
            finding_id = f"FINDING-{rule_id}-{int(now.timestamp())}-{abs(hash(asset + privilege)) % 10000:04d}"
            finding = Finding(
                id=finding_id,
                rule_id=rule_id,
                user_email=user_email,
                asset=asset,
                privilege=privilege,
                severity=rule_meta.get("severity", "HIGH"),
                detected_at=now,
                evidence_summary=evidence_summary,
                recommended_action=rule_meta.get("recommended_action", "Revoke or re-certify access."),
                status="OPEN",
                owner=rule_meta.get("owner", "SecOps"),
                due_date=due_date
            )
            db.add(finding)
            db.flush()

        # Check if an active exception exists for this finding
        active_exception = db.query(ExceptionRecord).filter(
            ExceptionRecord.finding_id == finding.id,
            ExceptionRecord.status == "ACTIVE",
            ExceptionRecord.expires_at > now
        ).first()

        if active_exception:
            finding.status = "EXCEPTION_APPROVED"
            decision = "EXCEPTION_ACTIVE"
            remediation = f"Access temporarily accepted under Exception #{active_exception.id} (Expires: {active_exception.expires_at.isoformat()})"
        else:
            decision = "VIOLATION_FLAGGED"
            remediation = finding.recommended_action

        # Generate cryptographic audit evidence
        EvidenceEngine.create_evidence(
            db=db,
            rule_id=rule_id,
            input_source=input_source,
            finding_id=finding.id,
            decision=decision,
            remediation_action=remediation,
            status=finding.status,
            evidence_details={
                "finding_id": finding.id,
                "rule_id": rule_id,
                "user_email": user_email,
                "asset": asset,
                "privilege": privilege,
                "severity": finding.severity,
                "evidence_summary": evidence_summary,
                "detected_at": now.isoformat()
            }
        )

        return finding

    # RULE-001: Terminated user retains privileged access
    def _eval_rule_001(self, db: Session, now: datetime) -> list[Finding]:
        findings = []
        rule_id = "RULE-001"
        
        query = db.query(Account, Identity, Entitlement).join(
            Identity, Account.identity_id == Identity.id
        ).join(
            Entitlement, Entitlement.account_id == Account.id
        ).filter(
            Identity.hr_status == "terminated",
            Account.is_active == True,
            Entitlement.privilege_level.in_(["critical_admin", "admin"])
        ).all()

        for acc, ident, ent in query:
            summary = f"Terminated employee '{ident.canonical_email}' (terminated {ident.termination_date}) holds active privileged entitlement '{ent.resource_name}' on system '{acc.system_name}'."
            f = self._upsert_finding(
                db, rule_id, ident.canonical_email,
                asset=f"{acc.system_name}:{acc.native_username}",
                privilege=ent.resource_name,
                evidence_summary=summary,
                input_source="Workday_HRIS + Cloud_IAM_API",
                now=now
            )
            findings.append(f)
        return findings

    # RULE-002: Privileged account has no owner
    def _eval_rule_002(self, db: Session, now: datetime) -> list[Finding]:
        findings = []
        rule_id = "RULE-002"

        query = db.query(Account, Entitlement).join(
            Entitlement, Entitlement.account_id == Account.id
        ).filter(
            Account.account_type == "human",
            Account.identity_id.is_(None),
            Account.owner_email.is_(None),
            Entitlement.privilege_level.in_(["critical_admin", "admin"])
        ).all()

        for acc, ent in query:
            summary = f"Human account '{acc.native_username}' on system '{acc.system_name}' holds privileged role '{ent.resource_name}' but is not mapped to any active employee."
            f = self._upsert_finding(
                db, rule_id, user_email="UNOWNED",
                asset=f"{acc.system_name}:{acc.native_username}",
                privilege=ent.resource_name,
                evidence_summary=summary,
                input_source="Cloud_IAM_API + Identity_Mapper",
                now=now
            )
            findings.append(f)
        return findings

    # RULE-003: Privileged access exists without recent review (>90 days)
    def _eval_rule_003(self, db: Session, now: datetime) -> list[Finding]:
        findings = []
        rule_id = "RULE-003"
        cutoff = now - timedelta(days=90)

        query = db.query(Account, Identity, Entitlement).join(
            Identity, Account.identity_id == Identity.id
        ).join(
            Entitlement, Entitlement.account_id == Account.id
        ).filter(
            Entitlement.privilege_level.in_(["critical_admin", "admin"]),
            (Entitlement.last_reviewed_at.is_(None)) | (Entitlement.last_reviewed_at < cutoff)
        ).all()

        for acc, ident, ent in query:
            last_rev_str = ent.last_reviewed_at.strftime("%Y-%m-%d") if ent.last_reviewed_at else "Never"
            summary = f"Privileged entitlement '{ent.resource_name}' for user '{ident.canonical_email}' was last reviewed on {last_rev_str}, exceeding the 90-day SLA."
            f = self._upsert_finding(
                db, rule_id, ident.canonical_email,
                asset=f"{acc.system_name}:{acc.native_username}",
                privilege=ent.resource_name,
                evidence_summary=summary,
                input_source="Access_Review_Ledger",
                now=now
            )
            findings.append(f)
        return findings

    # RULE-004: Privileged access inconsistent with job role
    def _eval_rule_004(self, db: Session, now: datetime) -> list[Finding]:
        findings = []
        rule_id = "RULE-004"
        approved_depts = ["Engineering", "DevOps", "Security", "IT"]

        query = db.query(Account, Identity, Entitlement).join(
            Identity, Account.identity_id == Identity.id
        ).join(
            Entitlement, Entitlement.account_id == Account.id
        ).filter(
            Identity.department.not_in(approved_depts),
            Entitlement.privilege_level.in_(["critical_admin", "admin"])
        ).all()

        for acc, ident, ent in query:
            summary = f"User '{ident.canonical_email}' in non-technical department '{ident.department}' holds critical privilege '{ent.resource_name}' on '{acc.system_name}'."
            f = self._upsert_finding(
                db, rule_id, ident.canonical_email,
                asset=f"{acc.system_name}:{acc.native_username}",
                privilege=ent.resource_name,
                evidence_summary=summary,
                input_source="Workday_OrgTree + IAM_Entitlements",
                now=now
            )
            findings.append(f)
        return findings

    # RULE-005: Inactive privileged account (>30 days)
    def _eval_rule_005(self, db: Session, now: datetime) -> list[Finding]:
        findings = []
        rule_id = "RULE-005"
        cutoff = now - timedelta(days=30)

        query = db.query(Account, Identity, Entitlement).outerjoin(
            Identity, Account.identity_id == Identity.id
        ).join(
            Entitlement, Entitlement.account_id == Account.id
        ).filter(
            Account.is_active == True,
            Account.last_login_at < cutoff,
            Entitlement.privilege_level.in_(["critical_admin", "admin"])
        ).all()

        for acc, ident, ent in query:
            email = ident.canonical_email if ident else acc.owner_email or "UNKNOWN"
            last_login_str = acc.last_login_at.strftime("%Y-%m-%d") if acc.last_login_at else "Never"
            summary = f"Privileged account '{acc.native_username}' has been inactive since {last_login_str} (>30 days inactive)."
            f = self._upsert_finding(
                db, rule_id, email,
                asset=f"{acc.system_name}:{acc.native_username}",
                privilege=ent.resource_name,
                evidence_summary=summary,
                input_source="IdP_Authentication_Logs",
                now=now
            )
            findings.append(f)
        return findings

    # RULE-006: Privileged access granted without approval
    def _eval_rule_006(self, db: Session, now: datetime) -> list[Finding]:
        findings = []
        rule_id = "RULE-006"

        query = db.query(Account, Identity, Entitlement).outerjoin(
            Identity, Account.identity_id == Identity.id
        ).join(
            Entitlement, Entitlement.account_id == Account.id
        ).filter(
            Entitlement.approval_ref.is_(None),
            Entitlement.privilege_level.in_(["critical_admin", "admin"])
        ).all()

        for acc, ident, ent in query:
            email = ident.canonical_email if ident else acc.owner_email or "UNOWNED"
            summary = f"Privileged entitlement '{ent.resource_name}' granted to '{acc.native_username}' has no documented change ticket or approval reference."
            f = self._upsert_finding(
                db, rule_id, email,
                asset=f"{acc.system_name}:{acc.native_username}",
                privilege=ent.resource_name,
                evidence_summary=summary,
                input_source="Jira_Change_Audit_Sync",
                now=now
            )
            findings.append(f)
        return findings

    # RULE-007: Manager failed to complete review (SLA breach)
    def _eval_rule_007(self, db: Session, now: datetime) -> list[Finding]:
        findings = []
        rule_id = "RULE-007"

        query = db.query(Account, Identity, Entitlement).join(
            Identity, Account.identity_id == Identity.id
        ).join(
            Entitlement, Entitlement.account_id == Account.id
        ).filter(
            (Identity.manager_review_status == "OVERDUE") |
            ((Identity.manager_review_due_date.is_not(None)) & (Identity.manager_review_due_date < now))
        ).all()

        for acc, ident, ent in query:
            mgr_email = ident.manager_email or "UNASSIGNED_MANAGER"
            summary = f"Manager '{mgr_email}' failed to complete access review for subordinate '{ident.canonical_email}' within SLA."
            f = self._upsert_finding(
                db, rule_id, ident.canonical_email,
                asset=f"{acc.system_name}:{acc.native_username}",
                privilege=ent.resource_name,
                evidence_summary=summary,
                input_source="Access_Review_SLA_Tracker",
                now=now
            )
            findings.append(f)
        return findings

    # RULE-008: Service account lacks documented owner
    def _eval_rule_008(self, db: Session, now: datetime) -> list[Finding]:
        findings = []
        rule_id = "RULE-008"

        query = db.query(Account, Entitlement).join(
            Entitlement, Entitlement.account_id == Account.id
        ).filter(
            Account.account_type == "service_account",
            Account.owner_email.is_(None),
            Entitlement.privilege_level.in_(["critical_admin", "admin"])
        ).all()

        for acc, ent in query:
            summary = f"Service account '{acc.native_username}' holding role '{ent.resource_name}' lacks a documented engineering owner or team email."
            f = self._upsert_finding(
                db, rule_id, user_email="SERVICE_ACCOUNT_UNOWNED",
                asset=f"{acc.system_name}:{acc.native_username}",
                privilege=ent.resource_name,
                evidence_summary=summary,
                input_source="Cloud_IAM_Service_Account_Catalog",
                now=now
            )
            findings.append(f)
        return findings
