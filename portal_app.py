"""
portal_app.py — NIS2 Compliance Portal — Ichnobyte S.R.L.
Entry point per Render. Sostituisce app.py come comando di avvio.
Contiene: portal landing, enterprise dashboard, supplier portal, quick scan.
"""
from flask import (Flask, render_template_string, request, jsonify,
                   session, redirect, url_for, flash)
from db import (init_db, create_enterprise, get_enterprise_by_email,
                export_enterprise_data, import_enterprise_data,
                get_enterprise_by_id, verify_password,
                create_supplier, get_suppliers_by_enterprise,
                get_supplier_by_id, get_supplier_by_email,
                get_supplier_by_access_code, delete_supplier,
                create_task, get_tasks_by_supplier,
                get_tasks_by_enterprise_supplier, get_task_by_id,
                update_task_status, delete_task,
                create_submission, get_submission_by_task,
                get_enterprise_stats, get_supplier_stats)
from company_lookup import lookup_company
from domain_scanner import scan_domain
from scoring import calculate_nis2_score
import os, time, random, string, json, requests, dns.resolver, hashlib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', 'nis2-portal-ichnobyte-2025')

init_db()
verification_codes = {}

# ═══════════════════════════════════════════════════════════════
# QUESTIONARIO NIS2 FORNITORE — 19 domande in 9 sezioni
# basato su Proposta Assessment NIS2 Ichnobyte
# ═══════════════════════════════════════════════════════════════
SUPPLIER_QUESTIONNAIRE = [
    {"id":"sec1","section":"1 — Governance & CISO","icon":"ti-user-shield","art":"Art. 20 D.Lgs. 138/2024",
     "questions":[
        {"id":"g1","text":"Esiste un CISO o responsabile sicurezza con ruolo formalizzato, mandato scritto e budget dedicato?",
         "opts":[("si","Sì — ruolo formale con mandato e budget"),("parziale","Presente ma senza formalizzazione completa"),("no","No — nessun ruolo designato")]},
        {"id":"g2","text":"Esiste un processo documentato di gestione del rischio cyber, aggiornato almeno annualmente?",
         "opts":[("si","Sì — documentato e aggiornato regolarmente"),("parziale","Presente ma non aggiornato annualmente"),("no","No")]},
    ]},
    {"id":"sec2","section":"2 — Accesso Remoto & MFA","icon":"ti-login","art":"Art. 21.2.i D.Lgs. 138/2024",
     "questions":[
        {"id":"a1","text":"L'accesso remoto ai sistemi (inclusi quelli del cliente) è limitato a utenti nominativi con MFA obbligatoria?",
         "opts":[("si","Sì — MFA su tutti gli accessi remoti"),("parziale","MFA parzialmente implementata"),("no","No MFA")]},
        {"id":"a2","text":"Gli accessi remoti sono registrati in log centralizzati e monitorati attivamente con alert?",
         "opts":[("si","Sì — log centralizzati e alert configurati"),("parziale","Log presenti ma non monitorati attivamente"),("no","No log o monitoraggio")]},
        {"id":"a3","text":"Vengono utilizzate connessioni sicure (VPN, Zero Trust, bastion host) per tutti gli accessi remoti?",
         "opts":[("si","Sì — su tutti gli accessi remoti"),("parziale","Solo per accessi ai sistemi critici"),("no","No — accessi diretti non cifrati")]},
    ]},
    {"id":"sec3","section":"3 — Privileged Access Management","icon":"ti-key","art":"Art. 21.2.i D.Lgs. 138/2024",
     "questions":[
        {"id":"p1","text":"Gli account privilegiati (admin, root, service account) sono separati dagli account standard con workflow di approvazione?",
         "opts":[("si","Sì — PAM implementato con approvazione workflow"),("parziale","Separazione presente ma senza workflow"),("no","No — account condivisi o non segregati")]},
        {"id":"p2","text":"Il principio del minimo privilegio è applicato e gli accessi vengono revocati entro 24h dalla cessazione del rapporto?",
         "opts":[("si","Sì — least privilege + offboarding <24h documentato"),("parziale","Applicato parzialmente, tempi di revoca variabili"),("no","No")]},
    ]},
    {"id":"sec4","section":"4 — Incident Response","icon":"ti-alert-triangle","art":"Art. 21.2.b + Art. 24",
     "questions":[
        {"id":"i1","text":"Esiste un Incident Response Plan (IRP) formalizzato, testato almeno annualmente con procedure di escalation?",
         "opts":[("si","Sì — IRP formale testato con evidenza"),("parziale","Processo informale o IRP non testato"),("no","No IRP")]},
        {"id":"i2","text":"I tempi di notifica degli incidenti al cliente sono ≤24-48h dall'evento e inclusi nei contratti come SLA?",
         "opts":[("si","Sì — SLA notifica <24h definiti e contrattualizzati"),("parziale","Tempi definiti ma non contrattualizzati"),("no","No — nessun SLA di notifica")]},
        {"id":"i3","text":"Esiste un registro degli incidenti con classificazione, tempi di risposta e azioni correttive documentate?",
         "opts":[("si","Sì — registro formale con evidenza"),("parziale","Tracciamento informale"),("no","No")]},
    ]},
    {"id":"sec5","section":"5 — Business Continuity & DR","icon":"ti-refresh","art":"Art. 21.2.c D.Lgs. 138/2024",
     "questions":[
        {"id":"b1","text":"Esiste un Business Continuity Plan (BCP) formale per i servizi erogati al cliente, con scenari documentati?",
         "opts":[("si","Sì — BCP formale con scenari documentati"),("parziale","BCP presente ma non formalizzato"),("no","No BCP")]},
        {"id":"b2","text":"Sono definiti e documentati RTO e RPO per i servizi critici erogati, condivisibili con il cliente?",
         "opts":[("si","Sì — RTO/RPO definiti e condivisibili"),("parziale","Definiti internamente ma non documentati formalmente"),("no","No — RTO/RPO non definiti")]},
        {"id":"b3","text":"Il Disaster Recovery Plan viene testato periodicamente con evidenza documentata e risultati registrati?",
         "opts":[("si","Sì — test almeno annuale con log e risultati"),("parziale","Testato ma senza documentazione formale"),("no","No test DR")]},
    ]},
    {"id":"sec6","section":"6 — Supply Chain & Contratti","icon":"ti-link","art":"Art. 21.2.d D.Lgs. 138/2024",
     "questions":[
        {"id":"s1","text":"I contratti con i clienti NIS2 includono clausole di sicurezza, SLA di risposta agli incidenti e diritti di audit?",
         "opts":[("si","Sì — clausole NIS2 complete nei contratti"),("parziale","Clausole generiche, non specifiche NIS2"),("no","No clausole di sicurezza")]},
        {"id":"s2","text":"Esiste un processo di valutazione della sicurezza dei sotto-fornitori critici che accedono ai dati/sistemi del cliente?",
         "opts":[("si","Sì — audit/questionario periodico sotto-fornitori"),("parziale","Valutazione informale dei principali fornitori"),("no","No valutazione sotto-fornitori")]},
    ]},
    {"id":"sec7","section":"7 — Vulnerability & Patch Management","icon":"ti-shield","art":"Art. 21.2.e D.Lgs. 138/2024",
     "questions":[
        {"id":"v1","text":"Vengono eseguiti vulnerability assessment periodici (almeno semestrale) sull'infrastruttura che accede ai sistemi cliente?",
         "opts":[("si","Sì — VA almeno semestrale con report"),("parziale","VA occasionale o solo su richiesta"),("no","No VA periodici")]},
        {"id":"v2","text":"Esiste un processo di patch management con SLA per vulnerabilità critiche (CVSS≥9 patchate entro 72h)?",
         "opts":[("si","Sì — SLA patch critiche documentati e rispettati"),("parziale","Patch applicate ma senza SLA formali"),("no","No processo strutturato")]},
    ]},
    {"id":"sec8","section":"8 — Data Security & Crittografia","icon":"ti-lock","art":"Art. 21.2.h D.Lgs. 138/2024",
     "questions":[
        {"id":"d1","text":"I dati del cliente sono cifrati sia a riposo (at-rest) che in transito (TLS 1.2+)?",
         "opts":[("si","Sì — cifratura at-rest e in-transit certificata"),("parziale","Solo in transito o solo at-rest"),("no","No cifratura sistematica")]},
        {"id":"d2","text":"Esiste una policy di classificazione dei dati e i dati del cliente sono identificati e trattati come critici?",
         "opts":[("si","Sì — classificazione formale con livelli di protezione"),("parziale","Classificazione informale"),("no","No policy di classificazione")]},
    ]},
    {"id":"sec9","section":"9 — Formazione & Awareness","icon":"ti-school","art":"Art. 20 D.Lgs. 138/2024",
     "questions":[
        {"id":"f1","text":"Il personale con accesso ai sistemi o dati del cliente riceve formazione periodica su cybersicurezza e phishing?",
         "opts":[("si","Sì — formazione annuale con tracciamento e attestati"),("parziale","Formazione occasionale senza tracciamento"),("no","No formazione")]},
    ]},
]

TASK_TYPES = {
    "questionario_nis2":     "Questionario NIS2 Fornitore (19 domande)",
    "conferma_irp":          "Conferma: Incident Response Plan con SLA 24-48h",
    "conferma_bcp":          "Conferma: BCP/DRP con RTO/RPO documentati e testati",
    "conferma_clausole":     "Conferma: Clausole NIS2 nei contratti attivi",
    "conferma_mfa":          "Conferma: MFA attiva su tutti gli accessi remoti",
    "conferma_va":           "Conferma: Vulnerability Assessment semestrale",
    "conferma_formazione":   "Conferma: Formazione cybersicurezza annuale",
}

def score_questionnaire(answers: dict):
    total, max_s = 0, 0
    for sec in SUPPLIER_QUESTIONNAIRE:
        for q in sec['questions']:
            max_s += 3
            v = answers.get(q['id'], 'no')
            if v == 'si':       total += 3
            elif v == 'parziale': total += 1.5
    pct = round(total / max_s * 100) if max_s > 0 else 0
    return round(total, 1), pct

# ═══════════════════════════════════════════════════════════════
# SHARED STYLES & HELPERS
# ═══════════════════════════════════════════════════════════════
BASE_CSS = """
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
<style>
:root{
  --teal:#1ABCBC; --teal-dark:#0f9e9e; --teal-light:rgba(26,188,188,0.12);
  --navy:#0B1829; --navy2:#0f2035; --navy3:#152840;
  --blue:#185FA5; --blue-light:rgba(24,95,165,0.15);
  --text:#E2E8F0; --text2:#94A3B8; --text3:#64748B;
  --border:rgba(255,255,255,0.07); --border2:rgba(255,255,255,0.12);
  --red:#EF4444; --yellow:#F59E0B; --green:#10B981; --purple:#8B5CF6;
  --red-bg:rgba(239,68,68,0.1); --yellow-bg:rgba(245,158,11,0.1);
  --green-bg:rgba(16,185,129,0.1); --purple-bg:rgba(139,92,246,0.1);
  --radius:10px; --radius-sm:6px; --radius-lg:14px;
  --shadow:0 4px 24px rgba(0,0,0,0.3);
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Inter',system-ui,sans-serif;background:var(--navy);color:var(--text);min-height:100vh;font-size:14px;line-height:1.6}
a{color:var(--teal);text-decoration:none;transition:opacity .15s}
a:hover{opacity:.8}

/* ── Topbar ── */
.topbar{position:sticky;top:0;z-index:100;background:rgba(11,24,41,0.95);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);height:60px;display:flex;align-items:center;padding:0 28px;gap:24px}
.topbar-logo{display:flex;align-items:center;gap:0;text-decoration:none;flex-shrink:0}
.topbar-logo:hover{opacity:1}
.logo-text{font-size:20px;font-weight:700;letter-spacing:1.5px;color:#fff;font-family:'Inter',sans-serif}
.logo-badge{display:inline-block;font-size:10px;font-weight:600;color:var(--teal);background:var(--teal-light);border:1px solid rgba(26,188,188,0.3);border-radius:4px;padding:2px 7px;margin-left:10px;letter-spacing:.5px;vertical-align:middle}
.topbar-links{display:flex;align-items:center;gap:20px;margin-left:auto;font-size:13px}
.topbar-links a{color:var(--text2)}
.topbar-links a:hover{color:var(--teal)}
.topbar-user{display:flex;align-items:center;gap:8px;background:var(--navy3);border:1px solid var(--border2);border-radius:20px;padding:5px 12px 5px 8px;font-size:12px;color:var(--text2)}
.topbar-user i{color:var(--teal)}
.topbar-sep{color:var(--border2);margin:0 2px}

/* ── Layout ── */
.page{max-width:1140px;margin:0 auto;padding:32px 20px}
.page-sm{max-width:540px;margin:0 auto;padding:40px 20px}
.page-header{margin-bottom:28px}
.page-header h1{font-size:24px;font-weight:700;color:#fff;margin-bottom:4px}
.page-header p{color:var(--text2);font-size:14px}

/* ── Cards ── */
.card{background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;margin-bottom:20px}
.card-title{font-size:16px;font-weight:600;color:#fff;display:flex;align-items:center;gap:8px;margin-bottom:16px}
.card-title i{color:var(--teal)}

/* ── Stats ── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius);padding:18px;text-align:center;transition:border-color .2s}
.stat-card:hover{border-color:var(--teal)}
.stat-num{font-size:30px;font-weight:700;color:var(--teal)}
.stat-label{font-size:12px;color:var(--text2);margin-top:4px}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:var(--radius-sm);font-size:13px;font-weight:500;cursor:pointer;border:none;transition:all .15s;text-decoration:none}
.btn-primary{background:var(--teal);color:#0B1829}.btn-primary:hover{background:var(--teal-dark);opacity:1}
.btn-secondary{background:var(--blue);color:#fff}.btn-secondary:hover{opacity:.85}
.btn-success{background:#0f6e56;color:#fff}.btn-success:hover{opacity:.85}
.btn-danger{background:rgba(239,68,68,0.12);color:#EF4444;border:1px solid rgba(239,68,68,0.25)}.btn-danger:hover{background:rgba(239,68,68,0.2)}
.btn-outline{background:transparent;border:1px solid var(--border2);color:var(--text)}.btn-outline:hover{border-color:var(--teal);color:var(--teal)}
.btn-sm{padding:6px 12px;font-size:12px}
.btn-full{width:100%;justify-content:center;padding:12px}

/* ── Forms ── */
label{font-size:12px;color:var(--text2);display:block;margin:14px 0 5px;font-weight:500;letter-spacing:.3px;text-transform:uppercase}
input,select,textarea{width:100%;padding:10px 13px;background:var(--navy);border:1px solid var(--border2);border-radius:var(--radius-sm);color:var(--text);font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:border-color .15s}
input:focus,select:focus,textarea:focus{border-color:var(--teal);box-shadow:0 0 0 3px rgba(26,188,188,0.08)}
select option{background:var(--navy2)}
textarea{resize:vertical;min-height:80px}

/* ── Alerts ── */
.alert{padding:12px 16px;border-radius:var(--radius-sm);font-size:13px;margin-bottom:14px;display:flex;align-items:flex-start;gap:8px}
.alert i{flex-shrink:0;margin-top:1px}
.alert-error{background:var(--red-bg);border:1px solid rgba(239,68,68,0.3);color:#FCA5A5}
.alert-success{background:var(--green-bg);border:1px solid rgba(16,185,129,0.35);color:#6EE7B7}
.alert-info{background:rgba(26,188,188,0.07);border:1px solid rgba(26,188,188,0.25);color:var(--teal)}
.alert-warning{background:var(--yellow-bg);border:1px solid rgba(245,158,11,0.3);color:#FCD34D}

/* ── Table ── */
table{width:100%;border-collapse:collapse;font-size:13px}
th{padding:10px 12px;text-align:left;color:var(--text2);font-weight:500;border-bottom:1px solid var(--border);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
td{padding:11px 12px;border-bottom:1px solid var(--border);color:var(--text)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(26,188,188,0.04)}

/* ── Badges ── */
.badge{display:inline-flex;align-items:center;gap:3px;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600}
.badge-red{background:var(--red-bg);color:#FCA5A5}
.badge-yellow{background:var(--yellow-bg);color:#FCD34D}
.badge-green{background:var(--green-bg);color:#6EE7B7}
.badge-blue{background:var(--blue-light);color:#93C5FD}
.badge-teal{background:var(--teal-light);color:var(--teal)}
.badge-purple{background:var(--purple-bg);color:#C4B5FD}
.badge-gray{background:rgba(100,116,139,0.15);color:var(--text2)}

/* ── Progress ── */
.progress-bar{height:6px;background:var(--navy3);border-radius:3px;overflow:hidden}
.progress-fill{height:100%;border-radius:3px;transition:width .5s}

/* ── Questionnaire ── */
.section-header{background:rgba(26,188,188,0.06);border-left:3px solid var(--teal);border-radius:0 var(--radius-sm) var(--radius-sm) 0;padding:10px 14px;margin:20px 0 10px}
.section-header h3{font-size:13px;color:var(--teal);font-weight:600;margin:0}
.section-header small{color:var(--text3);font-size:11px}
.q-block{background:var(--navy);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;margin-bottom:8px;transition:border-color .2s}
.q-block:hover{border-color:var(--border2)}
.q-text{font-size:13px;color:var(--text);margin-bottom:10px;line-height:1.55}
.q-opts{display:flex;flex-direction:column;gap:6px}
.q-opt{display:flex;align-items:center;gap:10px;cursor:pointer;background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:9px 13px;font-size:13px;color:var(--text2);transition:all .15s}
.q-opt:hover{border-color:var(--teal);color:var(--text);background:var(--teal-light)}

/* ── Task rows ── */
.task-row{display:flex;align-items:center;gap:12px;padding:14px 16px;background:var(--navy);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:8px;transition:border-color .2s}
.task-row:hover{border-color:var(--border2)}
.task-icon{width:38px;height:38px;border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:16px}

/* ── Grid ── */
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:640px){.two-col,.form-row{grid-template-columns:1fr}.topbar-links .topbar-link-hide{display:none}}

/* ── Footer ── */
.footer{text-align:center;padding:28px 20px;margin-top:40px;border-top:1px solid var(--border);color:var(--text3);font-size:12px}
.footer a{color:var(--text3)}.footer a:hover{color:var(--teal)}
</style>
"""

# ── Logo SVG inline (O → scudo compliance) ─────────────────
LOGO_SVG = """<svg width="22" height="22" viewBox="0 0 22 22" xmlns="http://www.w3.org/2000/svg" style="display:inline-block;vertical-align:middle;margin:0 1px">
  <circle cx="11" cy="11" r="10.5" fill="white"/>
  <circle cx="11" cy="11" r="7.5" fill="#1ABCBC"/>
  <path d="M11 4.5 L16.5 7 V11.5 C16.5 15 13.8 17.8 11 19 C8.2 17.8 5.5 15 5.5 11.5 V7 Z" fill="white"/>
  <polyline points="8.5,11 10.2,13 14,9" stroke="#1ABCBC" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""


def nav(role='', user_name='', extra_links=''):
    logout_url = '/enterprise/logout' if role == 'enterprise' else '/supplier/logout' if role == 'supplier' else '/'
    role_label = {'enterprise': 'Enterprise', 'supplier': 'Fornitore'}.get(role, '')

    user_html = ''
    if user_name:
        user_html = (
            f'<div class="topbar-user">'
            f'<i class="ti ti-user-circle" style="font-size:16px"></i>'
            f'<span>{user_name}</span>'
            f'<span class="topbar-sep">·</span>'
            f'<a href="{logout_url}" style="color:var(--text3);font-size:11px">Esci</a>'
            f'</div>'
        )

    return (
        '<div class="topbar">'
        '<a href="/" class="topbar-logo">'
        '<span class="logo-text">ICHN' + LOGO_SVG + 'BYTE</span>'
        '<span class="logo-badge">NIS2 PORTAL</span>'
        '</a>'
        '<div class="topbar-links">'
        + extra_links +
        user_html +
        '</div>'
        '</div>'
    )


def footer():
    return (
        '<div class="footer">'
        '© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — '
        'P.IVA 03954630921 — '
        '<a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a>'
        '</div>'
    )


def flash_html(category='info'):
    msgs = []
    for cat, msg in (session.pop('_flashes', None) or []):
        css = 'success' if cat == 'success' else 'error' if cat == 'error' else 'info'
        msgs.append(f'<div class="alert alert-{css}">{msg}</div>')
    return ''.join(msgs)

# ═══════════════════════════════════════════════════════════════
# AUTH DECORATORS
# ═══════════════════════════════════════════════════════════════

def enterprise_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'enterprise_id' not in session:
            return redirect('/enterprise/login')
        return f(*args, **kwargs)
    return decorated

def supplier_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'supplier_id' not in session:
            return redirect('/supplier/login')
        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════════════════════════════
# LANDING PAGE
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def landing():
    return render_template_string(BASE_CSS + r"""
<body>
""" + nav() + r"""
<div class="page-sm" style="padding-top:48px">
    <div style="text-align:center;margin-bottom:40px">
        <i class="ti ti-shield-check" style="font-size:48px;color:#63b3ed"></i>
        <h1 style="margin-top:12px">NIS2 Compliance Portal</h1>
        <p style="margin-top:6px;font-size:15px">Seleziona il tuo profilo per accedere allo strumento appropriato</p>
    </div>

    <!-- CARD A: Soggetto NIS2 -->
    <div class="card" style="border-color:rgba(252,129,129,0.3);margin-bottom:16px">
        <div class="card-title">
            <i class="ti ti-building-skyscraper" style="color:#fc8181"></i>
            Soggetto NIS2 diretto
            <span class="badge badge-red" style="margin-left:auto">Essenziale / Importante</span>
        </div>
        <p style="margin-bottom:16px">La mia azienda rientra negli obblighi NIS2 (energia, sanità, PA, finanza, ICT, manifatturiero critico…) e devo gestire la compliance e la mia supply chain.</p>
        <div class="two-col">
            <a href="/enterprise/login" class="btn btn-primary" style="text-align:center">
                <i class="ti ti-building"></i> Portale Enterprise
            </a>
            <a href="/scan" class="btn btn-outline" style="text-align:center">
                <i class="ti ti-scan"></i> Quick Scan gratuito
            </a>
        </div>
        <div class="alert alert-info" style="margin-top:12px;font-size:12px">
            <i class="ti ti-info-circle" style="vertical-align:-2px"></i>
            Per soggetti Essenziali e Importanti il Quick Scan gratuito non copre gli obblighi legali completi del D.Lgs. 138/2024. Si consiglia il portale Enterprise.
        </div>
    </div>

    <!-- CARD B: Fornitore -->
    <div class="card" style="border-color:rgba(99,179,237,0.3)">
        <div class="card-title">
            <i class="ti ti-link" style="color:#63b3ed"></i>
            Fornitore di soggetti NIS2
            <span class="badge badge-blue" style="margin-left:auto">Supply Chain</span>
        </div>
        <p style="margin-bottom:16px">Fornisco servizi IT, consulenza o accesso a sistemi ad organizzazioni nei settori critici NIS2 e devo verificare la mia compliance o rispondere ai requisiti del mio cliente.</p>
        <div class="two-col">
            <a href="/supplier/login" class="btn btn-primary" style="text-align:center">
                <i class="ti ti-login"></i> Accesso fornitore
            </a>
            <a href="/scan" class="btn btn-outline" style="text-align:center">
                <i class="ti ti-scan"></i> Quick Scan gratuito
            </a>
        </div>
        <div class="alert alert-info" style="margin-top:12px;font-size:12px">
            <i class="ti ti-info-circle" style="vertical-align:-2px"></i>
            Se il tuo cliente ti ha inviato un codice di accesso, usa "Accesso fornitore" per completare i task assegnati e rendere visibile il tuo report al cliente.
        </div>
    </div>

    <p style="text-align:center;margin-top:24px;font-size:12px;color:#4a5568">
        Ichnobyte S.R.L. — NIS2 Compliance Portal v1.0
    </p>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

# ═══════════════════════════════════════════════════════════════
# ENTERPRISE — AUTH
# ═══════════════════════════════════════════════════════════════

@app.route('/enterprise/register', methods=['GET','POST'])
def enterprise_register():
    error = ''
    if request.method == 'POST':
        name     = request.form.get('name','').strip()
        email    = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        confirm  = request.form.get('confirm','')
        category = request.form.get('category','Importante')
        ateco    = request.form.get('ateco','').strip()
        if not all([name, email, password]):
            error = 'Compilare tutti i campi obbligatori.'
        elif password != confirm:
            error = 'Le password non coincidono.'
        elif len(password) < 8:
            error = 'Password di almeno 8 caratteri.'
        else:
            ok, msg = create_enterprise(name, email, password, category, ateco)
            if ok:
                ent = get_enterprise_by_email(email)
                session['enterprise_id']   = ent['id']
                session['enterprise_name'] = ent['name']
                return redirect('/enterprise/')
            else:
                error = msg or 'Errore durante la registrazione.'
    return render_template_string(BASE_CSS + f"""
<body>
{nav()}
<div class="page-sm">
    <div class="page-header" style="margin-top:32px">
        <h1>Registrazione Enterprise</h1>
        <p>Crea il tuo account per gestire la compliance e i fornitori</p>
    </div>
    {'<div class="alert alert-error">'+error+'</div>' if error else ''}
    <div class="card">
        <form method="post">
            <label>Nome azienda *</label>
            <input type="text" name="name" required placeholder="Es. Saras S.p.A.">
            <label>Email amministratore *</label>
            <input type="email" name="email" required>
            <div class="form-row">
                <div>
                    <label>Password *</label>
                    <input type="password" name="password" required>
                </div>
                <div>
                    <label>Conferma password *</label>
                    <input type="password" name="confirm" required>
                </div>
            </div>
            <label>Categoria NIS2</label>
            <select name="category">
                <option value="Essenziale">Essenziale</option>
                <option value="Importante" selected>Importante</option>
            </select>
            <label>Codice ATECO principale</label>
            <input type="text" name="ateco" placeholder="Es. 35.11">
            <button type="submit" class="btn btn-primary btn-full">Registrati</button>
        </form>
        <p style="text-align:center;margin-top:14px;font-size:13px">
            Hai già un account? <a href="/enterprise/login">Accedi</a>
        </p>
    </div>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

@app.route('/enterprise/login', methods=['GET','POST'])
def enterprise_login():
    error = ''
    if request.method == 'POST':
        email    = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        ent = get_enterprise_by_email(email)
        if ent and verify_password(password, ent['password_hash']):
            session['enterprise_id']   = ent['id']
            session['enterprise_name'] = ent['name']
            return redirect('/enterprise/')
        error = 'Email o password non corretti.'
    return render_template_string(BASE_CSS + f"""
<body>
{nav()}
<div class="page-sm">
    <div class="page-header" style="margin-top:40px;text-align:center">
        <i class="ti ti-building" style="font-size:36px;color:#fc8181"></i>
        <h1 style="margin-top:8px">Portale Enterprise</h1>
        <p>Accedi per gestire fornitori, task e compliance NIS2</p>
    </div>
    {'<div class="alert alert-error">'+error+'</div>' if error else ''}
    <div class="card">
        <form method="post">
            <label>Email aziendale</label>
            <input type="email" name="email" required autofocus>
            <label>Password</label>
            <input type="password" name="password" required>
            <button type="submit" class="btn btn-primary btn-full">Accedi</button>
        </form>
        <p style="text-align:center;margin-top:14px;font-size:13px">
            Prima volta? <a href="/enterprise/register">Crea account</a>
        </p>
    </div>
    <p style="text-align:center;font-size:12px;color:#4a5568;margin-top:16px">
        <a href="/">← Torna al portale</a>
    </p>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

@app.route('/enterprise/logout')
def enterprise_logout():
    session.clear()
    return redirect('/enterprise/login')

# ═══════════════════════════════════════════════════════════════
# ENTERPRISE — DASHBOARD
# ═══════════════════════════════════════════════════════════════

@app.route('/enterprise/')
@enterprise_required
def enterprise_dashboard():
    eid   = session['enterprise_id']
    name  = session['enterprise_name']
    stats = get_enterprise_stats(eid)
    sups  = get_suppliers_by_enterprise(eid)

    sup_rows = ''
    for s in sups:
        tasks = get_tasks_by_supplier(s['id'])
        done  = sum(1 for t in tasks if t['status'] == 'completato')
        total = len(tasks)
        pct   = round(done/total*100) if total else 0
        badge = f'<span class="badge badge-green">{pct}%</span>' if pct == 100 else f'<span class="badge badge-yellow">{done}/{total}</span>' if total else '<span class="badge badge-gray">0 task</span>'
        sup_rows += f"""
        <tr>
            <td><a href="/enterprise/fornitore/{s['id']}">{s['name']}</a></td>
            <td>{s['email']}</td>
            <td><code style="font-size:11px;color:#9f7aea">{s['access_code']}</code></td>
            <td>{badge} {'<span class="badge badge-green">Completato</span>' if pct==100 and total>0 else ''}</td>
            <td><a href="/enterprise/fornitore/{s['id']}" class="btn btn-outline btn-sm">Dettaglio</a></td>
        </tr>"""

    perc_done = round(stats['tasks_done']/stats['tasks_total']*100) if stats['tasks_total'] else 0

    return render_template_string(BASE_CSS + f"""
<body>
{nav('enterprise', name, '<a href="/enterprise/fornitori/aggiungi">+ Fornitore</a> <a href="/enterprise/export" style="color:#68d391">⬇ Esporta</a> <a href="/enterprise/import" style="color:#f6ad55">⬆ Importa</a>')}
<div class="page">
    <div class="page-header" style="margin-top:28px">
        <h1>Dashboard — {name}</h1>
        <p>Gestione supply chain e compliance NIS2 fornitori</p>
    </div>

    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-num">{stats['suppliers']}</div>
            <div class="stat-label">Fornitori registrati</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{stats['tasks_total']}</div>
            <div class="stat-label">Task assegnati</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#68d391">{stats['tasks_done']}</div>
            <div class="stat-label">Task completati</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#f6e05e">{stats['tasks_pending']}</div>
            <div class="stat-label">In attesa</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#b794f4">{stats['avg_score']}%</div>
            <div class="stat-label">Score medio fornitori</div>
        </div>
    </div>

    <div style="margin-bottom:20px">
        <div style="display:flex;justify-content:space-between;font-size:13px;color:#a0aec0;margin-bottom:6px">
            <span>Completamento complessivo supply chain</span>
            <span>{perc_done}%</span>
        </div>
        <div class="progress-bar">
            <div class="progress-fill" style="width:{perc_done}%;background:{'#68d391' if perc_done>70 else '#f6e05e' if perc_done>30 else '#fc8181'}"></div>
        </div>
    </div>

    <div class="card">
        <div class="card-title">
            <i class="ti ti-users"></i> Fornitori
            <a href="/enterprise/fornitori/aggiungi" class="btn btn-primary btn-sm" style="margin-left:auto">+ Aggiungi fornitore</a>
        </div>
        {'<p style="color:#718096;text-align:center;padding:20px">Nessun fornitore registrato. <a href="/enterprise/fornitori/aggiungi">Aggiungine uno</a>.</p>' if not sups else f'''
        <table>
            <thead><tr><th>Azienda</th><th>Email</th><th>Codice accesso</th><th>Avanzamento</th><th></th></tr></thead>
            <tbody>{sup_rows}</tbody>
        </table>'''}
    </div>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

# ═══════════════════════════════════════════════════════════════
# ENTERPRISE — GESTIONE FORNITORI
# ═══════════════════════════════════════════════════════════════

@app.route('/enterprise/fornitori/aggiungi', methods=['GET','POST'])
@enterprise_required
def enterprise_add_supplier():
    eid  = session['enterprise_id']
    name = session['enterprise_name']
    error = ''
    if request.method == 'POST':
        s_name    = request.form.get('name','').strip()
        s_email   = request.form.get('email','').strip().lower()
        s_pass    = request.form.get('password','').strip()
        s_contact = request.form.get('contact_name','').strip()
        s_ateco   = request.form.get('ateco','').strip()
        s_notes   = request.form.get('notes','').strip()
        s_domain  = request.form.get('domain','').strip()
        if not all([s_name, s_email, s_pass]):
            error = 'Nome, email e password sono obbligatori.'
        else:
            sid, code, err = create_supplier(eid, s_name, s_email, s_pass,
                                              s_contact, s_ateco, s_notes, s_domain)
            if err:
                error = err
            else:
                return redirect(f'/enterprise/fornitore/{sid}?nuovo=1&code={code}')

    return render_template_string(BASE_CSS + f"""
<body>
{nav('enterprise', name, '<a href="/enterprise/">← Dashboard</a>')}
<div class="page-sm">
    <div class="page-header" style="margin-top:28px">
        <h1>Aggiungi Fornitore</h1>
        <p>Crea l'anagrafica e le credenziali di accesso per il tuo fornitore</p>
    </div>
    {'<div class="alert alert-error">'+error+'</div>' if error else ''}
    <div class="card">
        <form method="post">
            <h3>Dati aziendali</h3>
            <label>Ragione sociale *</label>
            <input type="text" name="name" required placeholder="Es. Tecno Sistemi S.r.l.">
            <div class="form-row">
                <div>
                    <label>Codice ATECO</label>
                    <input type="text" name="ateco" placeholder="Es. 62.01">
                </div>
                <div>
                    <label>Dominio web</label>
                    <input type="text" name="domain" placeholder="Es. tecnosistemi.it">
                </div>
            </div>
            <label>Referente sicurezza</label>
            <input type="text" name="contact_name" placeholder="Nome e cognome referente NIS2">
            <label>Note interne</label>
            <textarea name="notes" placeholder="Tipo di servizio fornito, criticità, ecc."></textarea>

            <h3 style="margin-top:20px">Credenziali di accesso</h3>
            <p style="font-size:12px;color:#718096;margin-bottom:8px">Il fornitore userà queste credenziali per accedere al portale e completare i task assegnati.</p>
            <label>Email fornitore *</label>
            <input type="email" name="email" required placeholder="referente@fornitore.it">
            <label>Password accesso *</label>
            <input type="password" name="password" required placeholder="Min. 8 caratteri">

            <button type="submit" class="btn btn-primary btn-full">Crea fornitore e genera codice accesso</button>
        </form>
    </div>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

@app.route('/enterprise/fornitore/<int:sid>')
@enterprise_required
def enterprise_supplier_detail(sid):
    eid    = session['enterprise_id']
    name   = session['enterprise_name']
    sup    = get_supplier_by_id(sid)
    if not sup or sup['enterprise_id'] != eid:
        return redirect('/enterprise/')

    nuovo = request.args.get('nuovo','')
    code  = request.args.get('code','')
    tasks = get_tasks_by_enterprise_supplier(eid, sid)

    def status_badge(s):
        m = {'assegnato':'badge-yellow','in_corso':'badge-blue','completato':'badge-green','scaduto':'badge-red'}
        return f'<span class="badge {m.get(s,"badge-gray")}">{s}</span>'

    task_rows = ''
    for t in tasks:
        sub = get_submission_by_task(t['id'])
        score_html = f'<span style="color:#68d391;font-weight:600">{sub["score_pct"]}%</span>' if sub else '<span style="color:#718096">—</span>'
        task_rows += f"""
        <tr>
            <td>{t['title']}</td>
            <td>{status_badge(t['status'])}</td>
            <td style="font-size:12px;color:#718096">{t['due_date'] or '—'}</td>
            <td>{score_html}</td>
            <td>
                {'<a href="/enterprise/submission/'+str(t['id'])+'" class="btn btn-outline btn-sm">Vedi risposta</a>' if sub else ''}
                <a href="/enterprise/task/elimina/'+str(t['id'])+'" class="btn btn-danger btn-sm" onclick="return confirm('Eliminare questo task?')">Elimina</a>
            </td>
        </tr>"""

    return render_template_string(BASE_CSS + f"""
<body>
{nav('enterprise', name, '<a href="/enterprise/">← Dashboard</a>')}
<div class="page">
    <div style="margin-top:28px">
        {'<div class="alert alert-success"><i class="ti ti-check"></i> Fornitore creato. Codice accesso: <strong>'+code+'</strong> — condividilo con il fornitore.</div>' if nuovo else ''}

        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:20px;flex-wrap:wrap;margin-bottom:24px">
            <div>
                <h1>{sup['name']}</h1>
                <p style="margin-top:4px">{sup['email']} {'• '+sup['contact_name'] if sup['contact_name'] else ''} {'• ATECO '+sup['ateco'] if sup['ateco'] else ''}</p>
            </div>
            <div style="text-align:right">
                <div style="font-size:12px;color:#a0aec0;margin-bottom:4px">Codice accesso fornitore</div>
                <code style="font-size:16px;color:#9f7aea;background:rgba(159,122,234,0.1);padding:6px 12px;border-radius:6px">{sup['access_code']}</code>
            </div>
        </div>

        {'<div class="alert alert-info" style="font-size:12px"><strong>Note:</strong> '+sup['notes']+'</div>' if sup['notes'] else ''}

        <div class="card">
            <div class="card-title">
                <i class="ti ti-list-check"></i> Task assegnati
                <a href="/enterprise/task/assegna/{sid}" class="btn btn-primary btn-sm" style="margin-left:auto">+ Assegna task</a>
            </div>
            {'<p style="color:#718096;text-align:center;padding:20px">Nessun task assegnato. <a href="/enterprise/task/assegna/'+str(sid)+'">Assegna il primo task</a>.</p>' if not tasks else f'''
            <table>
                <thead><tr><th>Task</th><th>Stato</th><th>Scadenza</th><th>Score</th><th></th></tr></thead>
                <tbody>{task_rows}</tbody>
            </table>'''}
        </div>

        <div style="margin-top:16px">
            <a href="/enterprise/fornitore/{sid}/elimina" class="btn btn-danger btn-sm"
               onclick="return confirm('Eliminare il fornitore e tutti i suoi dati?')">
               Elimina fornitore
            </a>
        </div>
    </div>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

@app.route('/enterprise/fornitore/<int:sid>/elimina')
@enterprise_required
def enterprise_delete_supplier(sid):
    eid = session['enterprise_id']
    sup = get_supplier_by_id(sid)
    if sup and sup['enterprise_id'] == eid:
        delete_supplier(sid)
    return redirect('/enterprise/')

@app.route('/enterprise/task/assegna/<int:sid>', methods=['GET','POST'])
@enterprise_required
def enterprise_assign_task(sid):
    eid  = session['enterprise_id']
    name = session['enterprise_name']
    sup  = get_supplier_by_id(sid)
    if not sup or sup['enterprise_id'] != eid:
        return redirect('/enterprise/')

    error = ''
    if request.method == 'POST':
        task_type   = request.form.get('task_type','')
        description = request.form.get('description','').strip()
        due_date    = request.form.get('due_date','').strip()
        priority    = request.form.get('priority','media')
        title       = TASK_TYPES.get(task_type, task_type)
        if not task_type:
            error = 'Seleziona un tipo di task.'
        else:
            create_task(sid, eid, task_type, title, description, due_date, priority)
            return redirect(f'/enterprise/fornitore/{sid}')

    opts = ''.join(f'<option value="{k}">{v}</option>' for k,v in TASK_TYPES.items())
    return render_template_string(BASE_CSS + f"""
<body>
{nav('enterprise', name, f'<a href="/enterprise/fornitore/{sid}">← {sup["name"]}</a>')}
<div class="page-sm">
    <div class="page-header" style="margin-top:28px">
        <h1>Assegna Task</h1>
        <p>Assegna un'attività di compliance a <strong style="color:#e2e8f0">{sup['name']}</strong></p>
    </div>
    {'<div class="alert alert-error">'+error+'</div>' if error else ''}
    <div class="card">
        <form method="post">
            <label>Tipo di task *</label>
            <select name="task_type" required>
                <option value="">— Seleziona —</option>
                {opts}
            </select>
            <label>Istruzioni aggiuntive</label>
            <textarea name="description" placeholder="Eventuali note o requisiti specifici per questo fornitore"></textarea>
            <div class="form-row">
                <div>
                    <label>Scadenza</label>
                    <input type="date" name="due_date">
                </div>
                <div>
                    <label>Priorità</label>
                    <select name="priority">
                        <option value="alta">Alta</option>
                        <option value="media" selected>Media</option>
                        <option value="bassa">Bassa</option>
                    </select>
                </div>
            </div>
            <button type="submit" class="btn btn-primary btn-full">Assegna task</button>
        </form>
    </div>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

@app.route('/enterprise/task/elimina/<int:tid>')
@enterprise_required
def enterprise_delete_task(tid):
    eid  = session['enterprise_id']
    task = get_task_by_id(tid)
    if task and task['enterprise_id'] == eid:
        delete_task(tid)
        return redirect(f'/enterprise/fornitore/{task["supplier_id"]}')
    return redirect('/enterprise/')

@app.route('/enterprise/submission/<int:tid>')
@enterprise_required
def enterprise_view_submission(tid):
    eid   = session['enterprise_id']
    name  = session['enterprise_name']
    task  = get_task_by_id(tid)
    if not task or task['enterprise_id'] != eid:
        return redirect('/enterprise/')
    sup = get_supplier_by_id(task['supplier_id'])
    sub = get_submission_by_task(tid)
    if not sub:
        return redirect(f'/enterprise/fornitore/{task["supplier_id"]}')

    answers = sub['answers'] if isinstance(sub['answers'], dict) else {}
    score_color = '#68d391' if sub['score_pct'] >= 70 else '#f6e05e' if sub['score_pct'] >= 40 else '#fc8181'

    sections_html = ''
    for sec in SUPPLIER_QUESTIONNAIRE:
        rows = ''
        for q in sec['questions']:
            ans = answers.get(q['id'], '—')
            color = '#68d391' if ans=='si' else '#f6e05e' if ans=='parziale' else '#fc8181'
            label = {'si':'Sì','parziale':'Parziale','no':'No'}.get(ans, ans)
            rows += f'<tr><td>{q["text"]}</td><td style="color:{color};font-weight:500">{label}</td></tr>'
        sections_html += f'<div class="section-header"><h3><i class="ti {sec["icon"]}" style="margin-right:6px"></i>{sec["section"]}</h3><small>{sec["art"]}</small></div><table>{rows}</table>'

    return render_template_string(BASE_CSS + f"""
<body>
{nav('enterprise', name, f'<a href="/enterprise/fornitore/{sup["id"]}">← {sup["name"]}</a>')}
<div class="page">
    <div style="margin-top:28px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px">
        <div>
            <h1>{task['title']}</h1>
            <p>Fornitore: <strong style="color:#e2e8f0">{sup['name']}</strong> — Completato il {sub['submitted_at'][:10]}</p>
        </div>
        <div style="text-align:center;background:rgba(255,255,255,0.04);border-radius:12px;padding:16px 24px;border:1px solid rgba(255,255,255,0.08)">
            <div style="font-size:36px;font-weight:700;color:{score_color}">{sub['score_pct']}%</div>
            <div style="font-size:12px;color:#718096">Score compliance</div>
        </div>
    </div>
    {'<div class="alert alert-info"><strong>Note fornitore:</strong> '+sub['notes']+'</div>' if sub.get('notes') else ''}
    <div class="card">
        <div class="card-title"><i class="ti ti-clipboard-list"></i> Risposte al questionario</div>
        {sections_html}
    </div>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

# ═══════════════════════════════════════════════════════════════
# SUPPLIER — AUTH
# ═══════════════════════════════════════════════════════════════

@app.route('/supplier/login', methods=['GET','POST'])
def supplier_login():
    error = ''
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        sup = get_supplier_by_email(email)
        if sup and verify_password(password, sup['password_hash']):
            ent = get_enterprise_by_id(sup['enterprise_id'])
            session['supplier_id']      = sup['id']
            session['supplier_name']    = sup['name']
            session['supplier_ent']     = ent['name'] if ent else ''
            session['supplier_ent_id']  = sup['enterprise_id']
            return redirect('/supplier/')
        error = 'Email o password non corretti.'
    return render_template_string(BASE_CSS + f"""
<body>
{nav()}
<div class="page-sm">
    <div class="page-header" style="margin-top:40px;text-align:center">
        <i class="ti ti-link" style="font-size:36px;color:#63b3ed"></i>
        <h1 style="margin-top:8px">Portale Fornitore</h1>
        <p>Accedi per visualizzare e completare i task assegnati dal tuo cliente</p>
    </div>
    {'<div class="alert alert-error">'+error+'</div>' if error else ''}
    <div class="card">
        <form method="post">
            <label>Email fornitore</label>
            <input type="email" name="email" required autofocus>
            <label>Password</label>
            <input type="password" name="password" required>
            <button type="submit" class="btn btn-primary btn-full">Accedi</button>
        </form>
        <div class="alert alert-info" style="margin-top:16px;font-size:12px">
            <i class="ti ti-info-circle"></i>
            Le credenziali ti sono state fornite dal tuo cliente (azienda Essenziale o Importante NIS2). Contatta il loro referente sicurezza se non le hai ricevute.
        </div>
    </div>
    <p style="text-align:center;font-size:12px;color:#4a5568;margin-top:16px">
        <a href="/">← Torna al portale</a>
    </p>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

@app.route('/supplier/logout')
def supplier_logout():
    session.clear()
    return redirect('/supplier/login')

# ═══════════════════════════════════════════════════════════════
# SUPPLIER — DASHBOARD
# ═══════════════════════════════════════════════════════════════

@app.route('/supplier/')
@supplier_required
def supplier_dashboard():
    sid   = session['supplier_id']
    name  = session['supplier_name']
    ent   = session.get('supplier_ent','')
    tasks = get_tasks_by_supplier(sid)
    stats = get_supplier_stats(sid)

    def status_badge(s):
        m = {'assegnato':('badge-yellow','ti-clock'),'in_corso':('badge-blue','ti-loader'),'completato':('badge-green','ti-check'),'scaduto':('badge-red','ti-x')}
        cls, icon = m.get(s, ('badge-gray','ti-minus'))
        return f'<span class="badge {cls}"><i class="ti {icon}" style="vertical-align:-1px"></i> {s}</span>'

    def priority_badge(p):
        m = {'alta':'badge-red','media':'badge-yellow','bassa':'badge-gray'}
        return f'<span class="badge {m.get(p,"badge-gray")}">{p}</span>'

    task_html = ''
    for t in tasks:
        sub = get_submission_by_task(t['id'])
        done = t['status'] == 'completato'
        task_html += f"""
        <div class="task-row">
            <div class="task-icon" style="background:{'rgba(104,211,145,0.15)' if done else 'rgba(99,179,237,0.1)'}">
                <i class="ti {'ti-check' if done else 'ti-clipboard-list'}" style="color:{'#68d391' if done else '#63b3ed'}"></i>
            </div>
            <div style="flex:1">
                <div style="font-size:13px;font-weight:500;color:#e2e8f0">{t['title']}</div>
                <div style="font-size:11px;color:#718096;margin-top:2px">
                    {status_badge(t['status'])} {priority_badge(t['priority'])}
                    {'• Scadenza: '+t['due_date'] if t['due_date'] else ''}
                    {'• Score: <strong style="color:#68d391">'+str(sub["score_pct"])+'%</strong>' if sub else ''}
                </div>
            </div>
            <a href="/supplier/task/{t['id']}" class="btn btn-{'outline' if done else 'primary'} btn-sm">
                {'Vedi risultato' if done else 'Completa'}
            </a>
        </div>"""

    return render_template_string(BASE_CSS + f"""
<body>
{nav('supplier', name, f'<span style="font-size:12px;color:#718096">Cliente: {ent}</span>')}
<div class="page">
    <div class="page-header" style="margin-top:28px">
        <h1>Dashboard Fornitore</h1>
        <p>Benvenuto {name} — task assegnati da <strong style="color:#e2e8f0">{ent}</strong></p>
    </div>

    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-num">{stats['tasks_total']}</div>
            <div class="stat-label">Task assegnati</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#f6e05e">{stats['tasks_pending']}</div>
            <div class="stat-label">Da completare</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#68d391">{stats['tasks_done']}</div>
            <div class="stat-label">Completati</div>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><i class="ti ti-list-check"></i> I tuoi task</div>
        {'<p style="color:#718096;text-align:center;padding:20px">Nessun task assegnato al momento.</p>' if not tasks else task_html}
    </div>

    <div class="card" style="border-color:rgba(99,179,237,0.2)">
        <div class="card-title"><i class="ti ti-info-circle" style="color:#63b3ed"></i> Come funziona</div>
        <p style="font-size:13px">
            Il tuo cliente ha assegnato i task sopra elencati per verificare la tua compliance NIS2.
            Completa ogni task rispondendo alle domande — le tue risposte saranno visibili al cliente nel suo portale.
            Al completamento riceverai un punteggio di compliance.
        </p>
    </div>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")

# ═══════════════════════════════════════════════════════════════
# SUPPLIER — TASK
# ═══════════════════════════════════════════════════════════════

@app.route('/supplier/task/<int:tid>', methods=['GET','POST'])
@supplier_required
def supplier_task(tid):
    sid  = session['supplier_id']
    name = session['supplier_name']
    ent  = session.get('supplier_ent', '')
    task = get_task_by_id(tid)
    if not task or task['supplier_id'] != sid:
        return redirect('/supplier/')

    task_id    = int(task['id'])
    task_type  = str(task['type'])
    task_title = str(task['title'])
    task_desc  = str(task['description'] or '')
    task_due   = str(task['due_date'] or '')
    is_questionnaire = (task_type == 'questionario_nis2')

    sub = get_submission_by_task(task_id)

    # ── Task già completato ───────────────────────────────────
    if sub:
        answers   = sub['answers'] if isinstance(sub['answers'], dict) else {}
        pct       = float(sub.get('score_pct') or 0)
        s_color   = '#68d391' if pct >= 70 else '#f6e05e' if pct >= 40 else '#fc8181'
        risk      = 'BASSO' if pct >= 70 else 'MEDIO' if pct >= 40 else 'ALTO'
        submitted = str(sub.get('submitted_at', ''))[:10]
        notes_val = str(sub.get('notes') or '')

        if is_questionnaire:
            body = ''
            for sec in SUPPLIER_QUESTIONNAIRE:
                rows = ''
                for q in sec['questions']:
                    ans   = answers.get(q['id'], 'no')
                    color = '#68d391' if ans == 'si' else '#f6e05e' if ans == 'parziale' else '#fc8181'
                    lbl   = {'si': '✅ Sì', 'parziale': '⚠️ Parziale', 'no': '❌ No'}.get(ans, ans)
                    rows += ('<tr>'
                             '<td style="font-size:13px;padding:8px 10px;color:#cbd5e0">' + q['text'] + '</td>'
                             '<td style="font-size:13px;padding:8px 10px;font-weight:600;white-space:nowrap;color:' + color + '">' + lbl + '</td>'
                             '</tr>')
                body += ('<div class="section-header">'
                         '<h3><i class="ti ' + sec['icon'] + '" style="margin-right:6px"></i>'
                         + sec['section'] + '</h3>'
                         '<small>' + sec['art'] + '</small></div>'
                         '<table style="width:100%;margin-bottom:8px">' + rows + '</table>')
        else:
            conf     = answers.get('conferma', '—')
            conf_lbl = {'si': '✅ Sì — requisito soddisfatto',
                        'parziale': '⚠️ Parzialmente implementato',
                        'no': '❌ Non ancora implementato'}.get(conf, conf)
            note_val = answers.get('note', '')
            body = ('<div style="font-size:16px;padding:20px 0;color:#e2e8f0">' + conf_lbl + '</div>')
            if note_val:
                body += '<p style="font-size:13px;color:#a0aec0;margin-top:4px">Note: ' + note_val + '</p>'

        notes_html = ''
        if notes_val:
            notes_html = '<div class="alert alert-info"><strong>Note aggiuntive:</strong> ' + notes_val + '</div>'

        page = (BASE_CSS
                + '<body>'
                + nav('supplier', name, '<a href="/supplier/">← Dashboard</a>')
                + '<div class="page">'
                + '<div style="margin-top:28px;margin-bottom:24px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:16px;align-items:flex-start">'
                + '<div><h1>' + task_title + '</h1><p>Completato il ' + submitted + '</p></div>'
                + '<div style="text-align:center;background:rgba(255,255,255,0.04);border-radius:12px;padding:16px 24px;border:1px solid rgba(255,255,255,0.08)">'
                + '<div style="font-size:36px;font-weight:700;color:' + s_color + '">' + str(round(pct)) + '%</div>'
                + '<div style="font-size:12px;color:#718096">Rischio: ' + risk + '</div>'
                + '</div></div>'
                + notes_html
                + '<div class="card">'
                + '<div class="card-title"><i class="ti ti-clipboard-check"></i> '
                + ('Risposte al questionario' if is_questionnaire else 'Risposta fornita') + '</div>'
                + body
                + '</div>'
                + '<div class="alert alert-success" style="margin-top:12px">'
                + '<i class="ti ti-check"></i> Task completato. Il tuo cliente può visualizzare questo report.'
                + '</div>'
                + '</div>' + footer() + '</body>')
        return render_template_string(page)

    # ── Form compilazione ─────────────────────────────────────
    error = ''
    if request.method == 'POST':
        if is_questionnaire:
            answers = {}
            for sec in SUPPLIER_QUESTIONNAIRE:
                for q in sec['questions']:
                    answers[q['id']] = request.form.get(q['id'], 'no')
            score, pct = score_questionnaire(answers)
            notes = request.form.get('notes', '').strip()
        else:
            conferma = request.form.get('conferma', '')
            if not conferma:
                error = 'Seleziona una risposta prima di inviare.'
            else:
                answers = {'conferma': conferma,
                           'note': request.form.get('notes', '')}
                score = 3.0 if conferma == 'si' else 1.5 if conferma == 'parziale' else 0.0
                pct   = int(score / 3 * 100)
                notes = request.form.get('notes', '').strip()

        if not error:
            create_submission(task_id, sid, answers, score, pct, notes)
            update_task_status(task_id, 'completato')
            return redirect('/supplier/task/' + str(task_id))

    form_body = _render_questionnaire_form() if is_questionnaire else _render_confirm_form()
    desc_html  = ('<div class="alert alert-info" style="font-size:13px">'
                  '<i class="ti ti-info-circle"></i> ' + task_desc + '</div>') if task_desc else ''
    error_html = '<div class="alert alert-error">' + error + '</div>' if error else ''
    due_html   = '&nbsp;|&nbsp;Scadenza: ' + task_due if task_due else ''

    page = (BASE_CSS
            + '<body>'
            + nav('supplier', name, '<a href="/supplier/">← Dashboard</a>')
            + '<div class="page">'
            + '<div class="page-header" style="margin-top:28px">'
            + '<h1>' + task_title + '</h1>'
            + '<p>Assegnato da: ' + ent + due_html + '</p>'
            + '</div>'
            + desc_html + error_html
            + '<form method="post">'
            + form_body
            + '<label style="margin-top:16px">Note aggiuntive (opzionale)</label>'
            + '<textarea name="notes" placeholder="Eventuali osservazioni, riferimenti documentali, ecc."></textarea>'
            + '<button type="submit" class="btn btn-success btn-full" style="margin-top:20px">'
            + '<i class="ti ti-send"></i> Invia risposta</button>'
            + '</form></div>' + footer() + '</body>')
    return render_template_string(page)



def _render_questionnaire_form():
    html = '<div class="alert alert-info" style="font-size:13px;margin-bottom:20px"><i class="ti ti-info-circle"></i> Rispondi a tutte le domande. Il report sarà visibile al tuo cliente nel portale enterprise.</div>'
    for sec in SUPPLIER_QUESTIONNAIRE:
        html += f'<div class="section-header"><h3><i class="ti {sec["icon"]}" style="margin-right:8px"></i>{sec["section"]}</h3><small>{sec["art"]}</small></div>'
        for q in sec['questions']:
            opts_html = ''
            for val, label in q['opts']:
                opts_html += f'<label class="q-opt"><input type="radio" name="{q["id"]}" value="{val}" required style="width:auto;accent-color:#63b3ed"> {label}</label>'
            html += f'<div class="q-block"><div class="q-text">{q["text"]}</div><div class="q-opts">{opts_html}</div></div>'
    return html

def _render_confirm_form(task):
    return f"""
    <div class="card">
        <p style="font-size:14px;margin-bottom:20px">Conferma lo stato di questo requisito per la tua organizzazione:</p>
        <div class="q-opts">
            <label class="q-opt"><input type="radio" name="conferma" value="si" style="width:auto;accent-color:#68d391"> ✅ Sì — requisito soddisfatto, documentazione disponibile</label>
            <label class="q-opt"><input type="radio" name="conferma" value="parziale" style="width:auto;accent-color:#f6e05e"> ⚠️ Parzialmente — in corso di implementazione</label>
            <label class="q-opt"><input type="radio" name="conferma" value="no" style="width:auto;accent-color:#fc8181"> ❌ No — requisito non ancora implementato</label>
        </div>
    </div>"""

# ═══════════════════════════════════════════════════════════════
# ENTERPRISE — EXPORT / IMPORT
# ═══════════════════════════════════════════════════════════════

@app.route('/enterprise/export')
@enterprise_required
def enterprise_export():
    from flask import Response
    from datetime import datetime
    eid  = session['enterprise_id']
    name = session['enterprise_name']
    data = export_enterprise_data(eid)
    filename = f"backup_nis2_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Type': 'application/json; charset=utf-8'
        }
    )


@app.route('/enterprise/import', methods=['GET','POST'])
@enterprise_required
def enterprise_import():
    eid  = session['enterprise_id']
    name = session['enterprise_name']
    result_html = ''

    if request.method == 'POST':
        f = request.files.get('backup_file')
        if not f or not f.filename:
            result_html = '<div class="alert alert-error">Nessun file selezionato.</div>'
        elif not f.filename.lower().endswith('.json'):
            result_html = '<div class="alert alert-error">File non valido — caricare un file .json esportato da questo portale.</div>'
        else:
            try:
                data = json.loads(f.read().decode('utf-8'))
                if 'enterprise' not in data or 'suppliers' not in data:
                    raise ValueError("Formato file non riconosciuto.")
                ok, msg, counts = import_enterprise_data(data)
                if ok:
                    result_html = (f'<div class="alert alert-success">'
                                   f'<i class="ti ti-check"></i> {msg}<br>'
                                   f'<small style="color:#a0aec0">Exported il: {data.get("exported_at","N/D")}</small>'
                                   f'</div>')
                else:
                    result_html = f'<div class="alert alert-error">{msg}</div>'
            except Exception as e:
                result_html = f'<div class="alert alert-error">Errore nel file: {str(e)}</div>'

    return render_template_string(BASE_CSS + """
<body>
""" + nav('enterprise', name, '<a href="/enterprise/">← Dashboard</a>') + """
<div class="page-sm">
    <div class="page-header" style="margin-top:28px">
        <h1>⬆ Importa dati</h1>
        <p>Ripristina fornitori, task e risposte da un file di backup esportato in precedenza</p>
    </div>
    """ + result_html + """
    <div class="card">
        <h3 style="margin-bottom:12px">Carica file di backup</h3>
        <form method="post" enctype="multipart/form-data">
            <div style="border:2px dashed rgba(255,255,255,0.15);border-radius:8px;padding:32px;text-align:center;margin-bottom:16px">
                <i class="ti ti-file-import" style="font-size:36px;color:#f6ad55;display:block;margin-bottom:12px"></i>
                <p style="margin-bottom:12px">Seleziona il file <code style="color:#68d391">.json</code> esportato dal portale</p>
                <input type="file" name="backup_file" accept=".json" required
                       style="width:auto;background:transparent;border:none;color:#63b3ed">
            </div>
            <div class="alert alert-info" style="font-size:12px">
                <i class="ti ti-info-circle"></i>
                I dati esistenti non vengono sovrascritti — vengono aggiunti solo i record mancanti.
                Le password dei fornitori rimangono funzionanti.
            </div>
            <button type="submit" class="btn btn-primary btn-full">
                <i class="ti ti-upload"></i> Importa dati
            </button>
        </form>
    </div>

    <div class="card" style="border-color:rgba(104,211,145,0.2)">
        <div class="card-title" style="font-size:15px">
            <i class="ti ti-download" style="color:#68d391"></i> Come esportare prima del deploy
        </div>
        <div style="counter-reset:steps">
            <div style="display:flex;gap:12px;margin-bottom:10px;align-items:flex-start">
                <span style="background:#185fa5;color:#fff;border-radius:50%;width:24px;height:24px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0">1</span>
                <p>Vai alla <a href="/enterprise/">dashboard enterprise</a> e clicca <strong style="color:#68d391">⬇ Esporta dati</strong></p>
            </div>
            <div style="display:flex;gap:12px;margin-bottom:10px;align-items:flex-start">
                <span style="background:#185fa5;color:#fff;border-radius:50%;width:24px;height:24px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0">2</span>
                <p>Salva il file <code style="color:#68d391">backup_nis2_YYYYMMDD.json</code> sul tuo computer</p>
            </div>
            <div style="display:flex;gap:12px;margin-bottom:10px;align-items:flex-start">
                <span style="background:#185fa5;color:#fff;border-radius:50%;width:24px;height:24px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0">3</span>
                <p>Fai il push su GitHub → Render fa il redeploy → database azzerato</p>
            </div>
            <div style="display:flex;gap:12px;align-items:flex-start">
                <span style="background:#0f6e56;color:#fff;border-radius:50%;width:24px;height:24px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0">4</span>
                <p>Torna qui, carica il file salvato → tutto ripristinato in pochi secondi</p>
            </div>
        </div>
    </div>
</div>
<div class="footer">© 2025 <a href="https://ichnobyte.it" target="_blank">Ichnobyte S.R.L.</a> — P.IVA 03954630921 — <a href="https://ichnobyte.it/privacy-policy">Privacy Policy</a></div>
</body>""")


# ═══════════════════════════════════════════════════════════════
# QUICK SCAN — route + API implementate direttamente
# ═══════════════════════════════════════════════════════════════

import re as _re, pathlib as _pathlib

def _get_scan_html():
    """Legge HTML_TEMPLATE da app.py senza importare Flask."""
    try:
        src = (_pathlib.Path(__file__).parent / 'app.py').read_text(encoding='utf-8')
        m = _re.search(r'HTML_TEMPLATE\s*=\s*r"""(.*?)"""', src, _re.DOTALL)
        if m:
            return m.group(1)
    except Exception as e:
        print(f'[WARN] HTML_TEMPLATE non trovato: {e}')
    return '<h2 style="color:#fc8181;padding:40px">Quick Scan non disponibile — app.py non trovato.</h2>'

@app.route('/scan')
def scan_page():
    return render_template_string(_get_scan_html())

# ── Helper per domain lookup (da app.py) ─────────────────────

import unicodedata as _ud

def _clean_name(name):
    name = _ud.normalize('NFKD', name).encode('ascii','ignore').decode('ascii').lower()
    import re as r
    for s in ['societa per azioni','societa a responsabilita limitata semplificata',
              'societa a responsabilita limitata','societa in accomandita semplice',
              'societa in nome collettivo','srls','srl','spa','snc','sas',
              'sapa','scrl','onlus','aps','ets','asd','coop','cooperativa',
              'group','gruppo','holding','italia']:
        name = r.sub(r'\b'+r.escape(s)+r'\b','',name)
    name = r.sub(r'[^a-z0-9 \-]','',name)
    name = r.sub(r'[\s\-]+',' ',name).strip().replace(' ','-')
    return name

def _resolves(domain):
    for rt in ('A','CNAME'):
        try:
            dns.resolver.resolve(domain, rt, lifetime=1)
            return True
        except Exception:
            pass
    return False

def _find_domain(company_name):
    base = _clean_name(company_name)
    if not base:
        return None
    first = base.split('-')[0]
    for b in ([base] + ([first] if first != base and len(first) > 2 else [])):
        for tld in ('.it','.com'):
            if _resolves(b + tld):
                return b + tld
    return base + '.it'

_INVALID = {'','n/d','nd','n.d.','non disponibile','null','none','-'}

@app.route('/api/test-lookup', methods=['POST'])
def api_test_lookup():
    vat = request.json.get('vat_number','')
    if not vat or len(vat) < 11:
        return jsonify({"success":False})
    company_data = lookup_company(vat)
    if company_data and company_data.get('name') and company_data['name'] != 'Partita IVA non trovata':
        ateco_raw = str(company_data.get('ateco','') or '').strip()
        if ateco_raw.lower() in _INVALID:
            ateco_raw = ''
        employees_raw = (company_data.get('employees','') or company_data.get('addetti','') or '')
        employees_count = None
        if str(employees_raw).strip().lower() not in _INVALID:
            try:
                n = int(''.join(filter(str.isdigit, str(employees_raw))))
                employees_count = n if n > 0 else None
            except (ValueError, TypeError):
                pass
        domain_hint = _find_domain(company_data['name'])
        return jsonify({"success":True,"name":company_data['name'],
                        "address":company_data.get('address',''),
                        "domain_hint":domain_hint,
                        "ateco":ateco_raw,
                        "employees_count":employees_count})
    return jsonify({"success":False})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    company_data = lookup_company(data.get('vat_number',''))
    if company_data is None:
        company_data = {"name":"Partita IVA non trovata","ateco":data.get('ateco','N/D'),
                        "employees":data.get('employees','N/D'),"revenue":data.get('revenue',''),
                        "is_supplier":bool(data.get('is_supplier',False)),"address":"N/D","status":"error"}
    else:
        company_data["ateco"]       = data.get('ateco','N/D')
        company_data["employees"]   = data.get('employees','N/D')
        company_data["revenue"]     = data.get('revenue','')
        company_data["is_supplier"] = bool(data.get('is_supplier',False))
    questions    = data.get('questions',{})
    domain       = data.get('domain','')
    scan_results = scan_domain(domain)
    score        = calculate_nis2_score(company_data, scan_results, questions)
    return jsonify({"company":company_data,"domain":domain,"score":score})

# ── OTP e DNS (da app.py, ricreati qui per autonomia) ─────────

verification_codes = {}

def _build_otp_html(code):
    return f"""<div style="font-family:Arial;max-width:480px;margin:0 auto;padding:32px;background:#0d1b2a;border-radius:12px;color:#e2e8f0">
      <h2 style="color:#63b3ed">NIS2 Portal — Ichnobyte</h2>
      <p style="color:#a0aec0">Codice di verifica:</p>
      <div style="font-size:40px;font-weight:700;letter-spacing:12px;color:#68d391;text-align:center;padding:20px;background:rgba(104,211,145,0.1);border-radius:8px;margin:20px 0">{code}</div>
      <p style="color:#718096;font-size:12px">Scade in 10 minuti.</p>
    </div>"""

def _send_email_api(to_email, code):
    from_email = os.environ.get('EMAIL_FROM_ADDRESS','noreply@ichnobyte.it')
    from_name  = os.environ.get('EMAIL_FROM_NAME','NIS2 Portal Ichnobyte')
    subject    = 'Codice di verifica — NIS2 Portal'
    brevo_key  = os.environ.get('BREVO_API_KEY','')
    sg_key     = os.environ.get('SENDGRID_API_KEY','')
    html_body  = _build_otp_html(code)
    if brevo_key:
        r = requests.post('https://api.brevo.com/v3/smtp/email',
            headers={'api-key':brevo_key,'Content-Type':'application/json'},
            json={'sender':{'name':from_name,'email':from_email},'to':[{'email':to_email}],'subject':subject,'htmlContent':html_body},
            timeout=12)
        if r.status_code in (200,201): return
        raise Exception(f"Brevo {r.status_code}: {r.text[:100]}")
    if sg_key:
        r = requests.post('https://api.sendgrid.com/v3/mail/send',
            headers={'Authorization':f'Bearer {sg_key}','Content-Type':'application/json'},
            json={'personalizations':[{'to':[{'email':to_email}]}],'from':{'email':from_email,'name':from_name},'subject':subject,'content':[{'type':'text/html','value':html_body}]},
            timeout=12)
        if r.status_code == 202: return
        raise Exception(f"SendGrid {r.status_code}")
    raise EnvironmentError("Configurare BREVO_API_KEY o SENDGRID_API_KEY")

@app.route('/api/send-otp', methods=['POST'])
def api_send_otp():
    email = request.json.get('email','').strip().lower()
    if not email or '@' not in email:
        return jsonify({"success":False,"message":"Email non valida"})
    existing = verification_codes.get(email,{})
    if isinstance(existing,dict) and existing.get('req_count',0)>=3 and time.time()-existing.get('req_time',0)<900:
        return jsonify({"success":False,"message":"Troppi tentativi. Attendi 15 minuti."})
    code = ''.join(random.choices(string.digits, k=6))
    verification_codes[email] = {"code":code,"expiry":time.time()+600,"attempts":0,"req_count":(existing.get('req_count',0)+1 if isinstance(existing,dict) else 1),"req_time":time.time()}
    api_configured = bool(os.environ.get('BREVO_API_KEY') or os.environ.get('SENDGRID_API_KEY'))
    if api_configured:
        try:
            _send_email_api(email, code)
            return jsonify({"success":True,"message":f"Codice inviato a {email}. Controlla la casella (e lo spam)."})
        except Exception as e:
            print(f"[OTP] Errore API: {e}")
            return jsonify({"success":False,"message":f"Errore invio: {str(e)[:80]}"})
    print(f"[DEV] OTP per {email}: {code}")
    return jsonify({"success":True,"message":f"[DEV] Codice: {code}","dev_code":code})

@app.route('/api/verify-otp', methods=['POST'])
def api_verify_otp():
    email = request.json.get('email','').strip().lower()
    code  = request.json.get('code','').strip()
    stored = verification_codes.get(email)
    if not isinstance(stored,dict):
        return jsonify({"valid":False,"message":"Nessun codice attivo. Richiedi un nuovo codice."})
    if time.time() > stored.get('expiry',0):
        verification_codes.pop(email,None)
        return jsonify({"valid":False,"message":"Codice scaduto. Richiedi un nuovo codice."})
    stored['attempts'] = stored.get('attempts',0)+1
    if stored['attempts'] > 5:
        verification_codes.pop(email,None)
        return jsonify({"valid":False,"message":"Troppi tentativi. Richiedi un nuovo codice."})
    if stored['code'] == code:
        verification_codes.pop(email,None)
        return jsonify({"valid":True,"message":"Email verificata correttamente."})
    return jsonify({"valid":False,"message":f"Codice non corretto. Tentativi rimanenti: {5-stored['attempts']}"})

@app.route('/api/verify-dns', methods=['POST'])
def api_verify_dns():
    email  = request.json.get('email','')
    domain = email.split('@')[-1] if '@' in email else ''
    res    = {"email":email,"domain":domain,"mx_valid":False,"mx_count":0,
              "spf_valid":False,"spf_strict":False,"spf_record":"",
              "dmarc_valid":False,"dmarc_policy":"","dmarc_rua":False,
              "dkim_verified":False,"dkim_selector":"","mta_sts":False,"score":0}
    try:
        mx = dns.resolver.resolve(domain,'MX',lifetime=3)
        res["mx_valid"]=True; res["mx_count"]=len(list(mx)); res["score"]+=5
    except Exception: pass
    try:
        for r in dns.resolver.resolve(domain,'TXT',lifetime=3):
            t=str(r)
            if 'v=spf1' in t:
                res["spf_valid"]=True; res["spf_record"]=t[:120]
                res["spf_strict"]='-all' in t
                res["score"]+=5 if res["spf_strict"] else 3; break
    except Exception: pass
    try:
        for r in dns.resolver.resolve(f'_dmarc.{domain}','TXT',lifetime=3):
            t=str(r)
            if 'v=DMARC1' in t:
                res["dmarc_valid"]=True; res["dmarc_rua"]='rua=' in t
                res["dmarc_policy"]='reject' if 'p=reject' in t else 'quarantine' if 'p=quarantine' in t else 'none'
                res["score"]+=8 if res["dmarc_policy"]=='reject' else 5 if res["dmarc_policy"]=='quarantine' else 2; break
    except Exception: pass
    for sel in ['default','google','mail','smtp','dkim','selector1','selector2','k1','k2','s1','s2','email','mx','protonmail','amazonses']:
        try:
            dns.resolver.resolve(f'{sel}._domainkey.{domain}','TXT',lifetime=2)
            res["dkim_verified"]=True; res["dkim_selector"]=sel; res["score"]+=7; break
        except Exception: continue
    try:
        for r in dns.resolver.resolve(f'_mta-sts.{domain}','TXT',lifetime=3):
            if 'v=STSv1' in str(r):
                res["mta_sts"]=True; res["score"]+=5; break
    except Exception: pass
    res["level"]="CONFORME" if res["score"]>=25 else "PARZIALE" if res["score"]>=12 else "NON CONFORME"
    return jsonify({"success":True,"results":res})



# ═══════════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT',5000)))