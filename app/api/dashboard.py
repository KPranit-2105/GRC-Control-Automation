from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Finding, AuditEvidence, ExceptionRecord

dashboard_router = APIRouter(tags=["Compliance Dashboard"])

@dashboard_router.get("/dashboard", response_class=HTMLResponse)
def render_dashboard(db: Session = Depends(get_db)):
    findings = db.query(Finding).order_by(Finding.detected_at.desc()).all()
    evidence_count = db.query(AuditEvidence).count()
    exception_count = db.query(ExceptionRecord).filter(ExceptionRecord.status == "ACTIVE").count()

    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    rows_html = ""
    for f in findings:
        badge_color = "bg-red-100 text-red-800" if f.severity == "CRITICAL" else ("bg-orange-100 text-orange-800" if f.severity == "HIGH" else "bg-yellow-100 text-yellow-800")
        status_color = "bg-red-50 text-red-700 border-red-200" if f.status == "OPEN" else "bg-green-50 text-green-700 border-green-200"
        
        user_str = f.user_email or '<span class="text-gray-400 font-mono">UNOWNED</span>'
        rows_html += f"""
        <tr class="hover:bg-gray-50 border-b border-gray-100 transition-colors">
            <td class="py-3 px-4 font-mono text-xs text-gray-500">{f.id}</td>
            <td class="py-3 px-4 font-mono text-xs text-indigo-600 font-semibold">{f.rule_id}</td>
            <td class="py-3 px-4 text-sm text-gray-800">{user_str}</td>
            <td class="py-3 px-4 text-xs font-mono text-gray-600">{f.asset}</td>
            <td class="py-3 px-4 text-xs text-gray-700 max-w-xs truncate" title="{f.evidence_summary}">{f.evidence_summary}</td>
            <td class="py-3 px-4">
                <span class="px-2.5 py-1 text-xs font-semibold rounded-full {badge_color}">{f.severity}</span>
            </td>
            <td class="py-3 px-4">
                <span class="px-2 py-0.5 text-xs font-medium rounded border {status_color}">{f.status}</span>
            </td>
            <td class="py-3 px-4 text-xs text-gray-500">{f.due_date.strftime('%Y-%m-%d')}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GRC Control Automation Engine — Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-800 antialiased font-sans">
    <div class="min-h-screen flex flex-col">
        <!-- Top Navbar -->
        <header class="bg-slate-900 text-white border-b border-slate-800 shadow-md">
            <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <span class="p-2 bg-indigo-600 rounded-lg text-white font-black text-xl">GRC</span>
                    <div>
                        <h1 class="text-lg font-bold tracking-tight">Privileged Access Review Engine</h1>
                        <p class="text-xs text-slate-400 font-mono">Continuous Control Monitoring & Evidence Automation (Prototype)</p>
                    </div>
                </div>
                <div class="flex items-center space-x-3">
                    <button onclick="triggerScan()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm rounded-lg shadow transition flex items-center space-x-2">
                        <svg class="w-4 h-4 animate-spin hidden" id="scan-spinner" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                        <span>Run Scan Now</span>
                    </button>
                    <a href="/api/v1/evidence/export?format=markdown" target="_blank" class="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-lg border border-slate-700 transition">Export Markdown Report</a>
                    <a href="/api/v1/evidence/export?format=json" target="_blank" class="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-lg border border-slate-700 transition">Export JSON</a>
                </div>
            </div>
        </header>

        <!-- Main Body -->
        <main class="flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8">
            <!-- Disclaimer Banner -->
            <div class="bg-amber-50 border-l-4 border-amber-500 p-4 rounded-r-lg shadow-sm">
                <div class="flex items-center">
                    <svg class="w-5 h-5 text-amber-600 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <p class="text-sm text-amber-800 font-medium">
                        <strong>Fictional Portfolio Prototype</strong>: This dashboard demonstrates automated GRC control evaluation, finding tracking, and cryptographic evidence generation.
                    </p>
                </div>
            </div>

            <!-- Stats Overview Cards -->
            <div class="grid grid-cols-1 md:grid-cols-5 gap-5">
                <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
                    <p class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Findings</p>
                    <p class="text-3xl font-extrabold text-slate-900 mt-2">{len(findings)}</p>
                    <p class="text-xs text-slate-400 mt-1">Across 8 Rule Scans</p>
                </div>
                <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm border-l-4 border-l-red-500">
                    <p class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Critical Severity</p>
                    <p class="text-3xl font-extrabold text-red-600 mt-2">{critical_count}</p>
                    <p class="text-xs text-slate-400 mt-1">Immediate SLA Revocation</p>
                </div>
                <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm border-l-4 border-l-orange-500">
                    <p class="text-xs font-semibold text-slate-500 uppercase tracking-wider">High Severity</p>
                    <p class="text-3xl font-extrabold text-orange-600 mt-2">{high_count}</p>
                    <p class="text-xs text-slate-400 mt-1">SLA Action Required</p>
                </div>
                <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
                    <p class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Audit Evidence Hashing</p>
                    <p class="text-3xl font-extrabold text-indigo-600 mt-2">{evidence_count}</p>
                    <p class="text-xs text-slate-400 mt-1">SHA-256 Ledger Entries</p>
                </div>
                <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
                    <p class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Quarterly Hours Saved</p>
                    <p class="text-3xl font-extrabold text-emerald-600 mt-2">62.5 hrs</p>
                    <p class="text-xs text-slate-400 mt-1">96% Manual Effort Reduction</p>
                </div>
            </div>

            <!-- Findings Table -->
            <div class="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                <div class="p-5 border-b border-slate-200 flex items-center justify-between">
                    <div>
                        <h2 class="text-base font-bold text-slate-900">Active Compliance Findings</h2>
                        <p class="text-xs text-slate-500">Real-time evaluation output from YAML detection rules engine</p>
                    </div>
                    <div class="text-xs text-slate-400 font-mono">Scope: SOC 2 CC6.1 - CC6.3 & PCI DSS 8.1.4</div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="bg-slate-100 text-slate-600 text-xs uppercase font-semibold border-b border-slate-200">
                                <th class="py-3 px-4">Finding ID</th>
                                <th class="py-3 px-4">Rule</th>
                                <th class="py-3 px-4">User / Account</th>
                                <th class="py-3 px-4">Target Asset</th>
                                <th class="py-3 px-4">Evidence Summary</th>
                                <th class="py-3 px-4">Severity</th>
                                <th class="py-3 px-4">Status</th>
                                <th class="py-3 px-4">SLA Due</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>

        <!-- Footer -->
        <footer class="bg-white border-t border-slate-200 py-4 px-6 text-center text-xs text-slate-500">
            DataStream Technologies GRC Control Automation Engine • Portfolio Prototype • Continuous Compliance Architecture
        </footer>
    </div>

    <script>
        async function triggerScan() {{
            const spinner = document.getElementById('scan-spinner');
            spinner.classList.remove('hidden');
            try {{
                const res = await fetch('/api/v1/scan', {{ method: 'POST' }});
                if (res.ok) {{
                    window.location.reload();
                }} else {{
                    alert('Scan failed: ' + res.statusText);
                }}
            }} catch (e) {{
                alert('Error running scan: ' + e);
            }} finally {{
                spinner.classList.add('hidden');
            }}
        }}
    </script>
</body>
</html>
"""
    return html_content
