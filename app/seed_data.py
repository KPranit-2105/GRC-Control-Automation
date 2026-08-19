from datetime import datetime, timedelta
from app.database import SessionLocal, engine, Base
from app.models import Identity, Account, Entitlement, Finding, ExceptionRecord, AuditEvidence

def seed_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        now = datetime.utcnow()

        # Manager hierarchy root
        vp_eng = Identity(
            id="ident_vp_eng",
            canonical_email="vp.engineering@datastream.io",
            first_name="Victoria",
            last_name="Pierce",
            employee_id="EMP-001",
            department="Engineering",
            job_title="VP of Engineering",
            manager_email=None,
            hr_status="active",
            manager_review_status="COMPLETED"
        )
        db.add(vp_eng)

        overdue_mgr = Identity(
            id="ident_overdue_mgr",
            canonical_email="overdue.manager@datastream.io",
            first_name="Marcus",
            last_name="Vance",
            employee_id="EMP-002",
            department="Engineering",
            job_title="Engineering Manager",
            manager_email="vp.engineering@datastream.io",
            hr_status="active",
            manager_review_status="OVERDUE",
            manager_review_due_date=now - timedelta(days=7)
        )
        db.add(overdue_mgr)

        sec_lead = Identity(
            id="ident_sec_lead",
            canonical_email="jane.ciso@datastream.io",
            first_name="Jane",
            last_name="Foster",
            employee_id="EMP-003",
            department="Security",
            job_title="Security Lead",
            manager_email="vp.engineering@datastream.io",
            hr_status="active",
            manager_review_status="COMPLETED"
        )
        db.add(sec_lead)

        # RULE-001: Terminated User
        term_user = Identity(
            id="ident_term_user",
            canonical_email="john.doe@datastream.io",
            first_name="John",
            last_name="Doe",
            employee_id="EMP-099",
            department="Engineering",
            job_title="Senior Backend Engineer",
            manager_email="overdue.manager@datastream.io",
            hr_status="terminated",
            termination_date=now - timedelta(days=10),
            manager_review_status="COMPLETED"
        )
        db.add(term_user)

        # RULE-003: Unreviewed Access
        unreviewed_user = Identity(
            id="ident_unreviewed_user",
            canonical_email="sarah.connor@datastream.io",
            first_name="Sarah",
            last_name="Connor",
            employee_id="EMP-104",
            department="DevOps",
            job_title="DevOps Engineer",
            manager_email="vp.engineering@datastream.io",
            hr_status="active",
            manager_review_status="COMPLETED"
        )
        db.add(unreviewed_user)

        # RULE-004: Role Mismatch
        mktg_user = Identity(
            id="ident_mktg_user",
            canonical_email="marketing.lead@datastream.io",
            first_name="Monica",
            last_name="Geller",
            employee_id="EMP-205",
            department="Marketing",
            job_title="Marketing Director",
            manager_email="vp.engineering@datastream.io",
            hr_status="active",
            manager_review_status="COMPLETED"
        )
        db.add(mktg_user)

        # RULE-005: Inactive User
        inactive_user = Identity(
            id="ident_inactive_user",
            canonical_email="bob.engineer@datastream.io",
            first_name="Robert",
            last_name="Paulson",
            employee_id="EMP-303",
            department="Engineering",
            job_title="Software Engineer",
            manager_email="overdue.manager@datastream.io",
            hr_status="active",
            manager_review_status="COMPLETED"
        )
        db.add(inactive_user)

        # RULE-006: Unapproved Grant Contractor
        contractor = Identity(
            id="ident_contractor",
            canonical_email="dave.contractor@datastream.io",
            first_name="David",
            last_name="Miller",
            employee_id="CON-901",
            department="Engineering",
            job_title="External Contractor",
            manager_email="overdue.manager@datastream.io",
            hr_status="active",
            manager_review_status="COMPLETED"
        )
        db.add(contractor)

        # RULE-007: Employee under overdue manager
        overdue_emp = Identity(
            id="ident_overdue_emp",
            canonical_email="alice.smith@datastream.io",
            first_name="Alice",
            last_name="Smith",
            employee_id="EMP-410",
            department="Engineering",
            job_title="Frontend Engineer",
            manager_email="overdue.manager@datastream.io",
            hr_status="active",
            manager_review_status="OVERDUE",
            manager_review_due_date=now - timedelta(days=7)
        )
        db.add(overdue_emp)

        db.commit()

        # ACCOUNTS & ENTITLEMENTS

        # 1. Terminated user account (RULE-001)
        acc_term = Account(
            id="acc_term",
            system_name="aws_iam",
            native_username="jdoe-admin",
            account_type="human",
            identity_id="ident_term_user",
            owner_email="john.doe@datastream.io",
            is_active=True,
            last_login_at=now - timedelta(days=2)
        )
        db.add(acc_term)
        db.add(Entitlement(
            id="ent_term",
            account_id="acc_term",
            resource_name="arn:aws:iam::123456789012:role/AdministratorAccess",
            privilege_level="critical_admin",
            granted_at=now - timedelta(days=180),
            approval_ref="JIRA-100",
            approved_by="vp.engineering@datastream.io"
        ))

        # 2. Unowned human account (RULE-002)
        acc_unowned = Account(
            id="acc_unowned",
            system_name="aws_iam",
            native_username="legacy-admin-user",
            account_type="human",
            identity_id=None,
            owner_email=None,
            is_active=True,
            last_login_at=now - timedelta(days=5)
        )
        db.add(acc_unowned)
        db.add(Entitlement(
            id="ent_unowned",
            account_id="acc_unowned",
            resource_name="arn:aws:iam::123456789012:role/SecurityAdmin",
            privilege_level="admin",
            granted_at=now - timedelta(days=365)
        ))

        # 3. Unreviewed access account (RULE-003)
        acc_unreviewed = Account(
            id="acc_unreviewed",
            system_name="aws_iam",
            native_username="sconnor",
            account_type="human",
            identity_id="ident_unreviewed_user",
            owner_email="sarah.connor@datastream.io",
            is_active=True,
            last_login_at=now - timedelta(days=1)
        )
        db.add(acc_unreviewed)
        db.add(Entitlement(
            id="ent_unreviewed",
            account_id="acc_unreviewed",
            resource_name="arn:aws:iam::123456789012:role/DevOpsAdmin",
            privilege_level="admin",
            granted_at=now - timedelta(days=200),
            approval_ref="JIRA-204",
            approved_by="vp.engineering@datastream.io",
            last_reviewed_at=now - timedelta(days=120)  # > 90 days ago
        ))

        # 4. Role mismatch account (RULE-004)
        acc_mktg = Account(
            id="acc_mktg",
            system_name="k8s",
            native_username="mlead",
            account_type="human",
            identity_id="ident_mktg_user",
            owner_email="marketing.lead@datastream.io",
            is_active=True,
            last_login_at=now - timedelta(days=3)
        )
        db.add(acc_mktg)
        db.add(Entitlement(
            id="ent_mktg",
            account_id="acc_mktg",
            resource_name="k8s:cluster-admin",
            privilege_level="critical_admin",
            granted_at=now - timedelta(days=60),
            approval_ref="JIRA-305"
        ))

        # 5. Inactive account (RULE-005)
        acc_inactive = Account(
            id="acc_inactive",
            system_name="github",
            native_username="beng-ds",
            account_type="human",
            identity_id="ident_inactive_user",
            owner_email="bob.engineer@datastream.io",
            is_active=True,
            last_login_at=now - timedelta(days=45)  # Inactive > 30 days
        )
        db.add(acc_inactive)
        db.add(Entitlement(
            id="ent_inactive",
            account_id="acc_inactive",
            resource_name="github:org-owner",
            privilege_level="admin",
            granted_at=now - timedelta(days=150)
        ))

        # 6. Unapproved grant account (RULE-006)
        acc_contractor = Account(
            id="acc_contractor",
            system_name="aws_iam",
            native_username="dcontractor",
            account_type="human",
            identity_id="ident_contractor",
            owner_email="dave.contractor@datastream.io",
            is_active=True,
            last_login_at=now - timedelta(days=1)
        )
        db.add(acc_contractor)
        db.add(Entitlement(
            id="ent_contractor",
            account_id="acc_contractor",
            resource_name="arn:aws:iam::123456789012:role/DatabaseAdmin",
            privilege_level="admin",
            granted_at=now - timedelta(days=15),
            approval_ref=None  # No approval ticket!
        ))

        # 7. Employee under overdue manager (RULE-007)
        acc_overdue = Account(
            id="acc_overdue",
            system_name="aws_iam",
            native_username="asmith-dev",
            account_type="human",
            identity_id="ident_overdue_emp",
            owner_email="alice.smith@datastream.io",
            is_active=True,
            last_login_at=now - timedelta(days=2)
        )
        db.add(acc_overdue)
        db.add(Entitlement(
            id="ent_overdue",
            account_id="acc_overdue",
            resource_name="arn:aws:iam::123456789012:role/PowerUserAccess",
            privilege_level="admin",
            granted_at=now - timedelta(days=100)
        ))

        # 8. Service Account without owner (RULE-008)
        acc_svc = Account(
            id="acc_svc_unowned",
            system_name="aws_iam",
            native_username="svc-deployment-pipeline",
            account_type="service_account",
            identity_id=None,
            owner_email=None,
            is_active=True,
            last_login_at=now - timedelta(days=1)
        )
        db.add(acc_svc)
        db.add(Entitlement(
            id="ent_svc",
            account_id="acc_svc_unowned",
            resource_name="arn:aws:iam::123456789012:role/DeploymentFullAccess",
            privilege_level="critical_admin",
            granted_at=now - timedelta(days=300)
        ))

        # COMPLIANT NEGATIVE TEST CASES

        # Compliant human account
        acc_good_human = Account(
            id="acc_good_human",
            system_name="aws_iam",
            native_username="jfoster-sec",
            account_type="human",
            identity_id="ident_sec_lead",
            owner_email="jane.ciso@datastream.io",
            is_active=True,
            last_login_at=now - timedelta(days=1)
        )
        db.add(acc_good_human)
        db.add(Entitlement(
            id="ent_good_human",
            account_id="acc_good_human",
            resource_name="arn:aws:iam::123456789012:role/SecurityAuditRole",
            privilege_level="admin",
            granted_at=now - timedelta(days=60),
            approval_ref="JIRA-501",
            approved_by="vp.engineering@datastream.io",
            last_reviewed_at=now - timedelta(days=10)
        ))

        # Compliant service account
        acc_good_svc = Account(
            id="acc_good_svc",
            system_name="aws_iam",
            native_username="svc-ci-cd-bot",
            account_type="service_account",
            identity_id=None,
            owner_email="devops-team@datastream.io",
            is_active=True,
            last_login_at=now - timedelta(days=1)
        )
        db.add(acc_good_svc)
        db.add(Entitlement(
            id="ent_good_svc",
            account_id="acc_good_svc",
            resource_name="arn:aws:iam::123456789012:role/ContinuousIntegrationRole",
            privilege_level="write",
            granted_at=now - timedelta(days=90),
            approval_ref="JIRA-602",
            approved_by="jane.ciso@datastream.io"
        ))

        db.commit()
        print("Database successfully seeded with realistic compliance test cases.")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
