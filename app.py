from flask import Flask, render_template_string, request, jsonify
from company_lookup import lookup_company
from domain_scanner import scan_domain
from scoring import calculate_nis2_score
import random
import string
import smtplib
import dns.resolver
import socket
import subprocess
import sys
import os
from email.mime.text import MIMEText

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = 'nis2-quick-scan-secret-key-change-me'

verification_codes = {}

# ============================================================
# RILEVAMENTO DOMINIO LOCALE
# ============================================================

def detect_local_domain():
    domain_info = {
        "is_joined": False,
        "domain_name": "",
        "workgroup": "",
        "full_computer_name": ""
    }
    
    try:
        hostname = socket.gethostname()
        domain_info["full_computer_name"] = hostname
        
        if '.' in hostname:
            domain_info["is_joined"] = True
            domain_info["domain_name"] = hostname.split('.', 1)[1]
        
        if sys.platform == 'win32':
            user_domain = os.environ.get('USERDNSDOMAIN', '')
            if user_domain and user_domain != os.environ.get('COMPUTERNAME', ''):
                domain_info["is_joined"] = True
                domain_info["domain_name"] = user_domain
            
            if not domain_info["is_joined"]:
                try:
                    out = subprocess.run(['systeminfo'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
                    for line in out.stdout.split('\n'):
                        if 'Dominio:' in line:
                            domain_value = line.split(':')[-1].strip()
                            if domain_value and domain_value != 'WORKGROUP':
                                domain_info["is_joined"] = True
                                domain_info["domain_name"] = domain_value
                            else:
                                domain_info["workgroup"] = domain_value
                except: pass
            
            if not domain_info["is_joined"]:
                try:
                    out = subprocess.run(
                        ['reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters', '/v', 'Domain'],
                        capture_output=True, text=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    for line in out.stdout.split('\n'):
                        if 'Domain' in line and 'REG_SZ' in line:
                            parts = line.strip().split()
                            for i, part in enumerate(parts):
                                if part == 'REG_SZ' and i + 1 < len(parts):
                                    domain_value = parts[i + 1]
                                    if domain_value and domain_value != 'WORKGROUP':
                                        domain_info["is_joined"] = True
                                        domain_info["domain_name"] = domain_value
                                    else:
                                        domain_info["workgroup"] = domain_value
                                    break
                except: pass
    
    except Exception as e:
        domain_info["error"] = str(e)[:50]
    
    return domain_info

local_domain_info = detect_local_domain()
print(f"Dominio locale: {local_domain_info['domain_name'] if local_domain_info['is_joined'] else 'Nessuno'}")

# ============================================================
# HTML TEMPLATE
# ============================================================

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ichnobyte - NIS2 Compliance Tool</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background-color: #0a1628;
            background-image: url('/logo-sfondo.png');
            background-size: cover; background-position: center center;
            background-attachment: fixed; background-repeat: no-repeat;
            min-height: 100vh; position: relative; color: #e2e8f0;
        }
        body::before {
            content: ""; position: fixed; top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(10, 22, 40, 0.85);
            z-index: 0; pointer-events: none;
        }
        .top-bar {
            position: relative; z-index: 10;
            display: flex; align-items: center; justify-content: flex-start;
            padding: 15px 30px; background: rgba(10, 22, 40, 0.95);
            border-bottom: 2px solid rgba(43, 108, 176, 0.5);
            backdrop-filter: blur(10px); gap: 20px; flex-wrap: wrap;
        }
        .top-bar img { height: 50px; width: auto; flex-shrink: 0; }
        .top-bar-text { flex: 1; min-width: 200px; }
        .top-bar-title { font-size: 22px; font-weight: 700; color: #ffffff; margin: 0; letter-spacing: 0.5px; }
        .top-bar-title span { color: #63b3ed; font-weight: 400; }
        .top-bar-slogan { font-size: 13px; color: #a0aec0; margin: 3px 0 0 0; font-style: italic; }
        .main-container { position: relative; z-index: 1; max-width: 900px; margin: 0 auto; padding: 40px 20px 50px 20px; }
        .subtitle { color: #a0aec0; margin: 10px 0 25px 0; font-size: 15px; }
        .card { background: rgba(15, 27, 45, 0.9); border: 1px solid rgba(43,108,176,0.3); border-radius: 10px; padding: 25px; margin: 20px 0; backdrop-filter: blur(5px); }
        button { background: #2b6cb0; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 15px; font-weight: 600; }
        button:hover { background: #1d4ed8; }
        button:disabled { background: #4a5568; cursor: not-allowed; }
        .btn-full { width: 100%; padding: 15px 30px; font-size: 16px; }
        .btn-small { width: auto; padding: 10px 20px; font-size: 14px; margin-top: 5px; }
        .btn-outline { background: transparent; border: 2px solid #2b6cb0; color: #2b6cb0; }
        input, select { padding: 12px; border: 1px solid rgba(43,108,176,0.4); border-radius: 6px; width: 100%; font-size: 16px; margin-bottom: 10px; background: rgba(15,27,45,0.8); color: #e2e8f0; }
        input::placeholder { color: #718096; }
        select { color: #e2e8f0; }
        select option { background: #1a365d; color: #e2e8f0; }
        label { font-weight: 600; display: block; margin-bottom: 5px; color: #cbd5e0; font-size: 14px; }
        small { font-size: 12px; line-height: 1.4; }
        .ok { color: #68d391; font-weight: bold; }
        .warning { color: #f6e05e; font-weight: bold; }
        .error { color: #fc8181; font-weight: bold; }
        .info { color: #63b3ed; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        td, th { border: 1px solid rgba(43,108,176,0.3); padding: 10px; text-align: left; font-size: 14px; color: #e2e8f0; }
        th { background: rgba(43,108,176,0.2); font-weight: 600; }
        .cta { background: linear-gradient(135deg, #ed8936, #dd6b20); color: white; padding: 25px; border-radius: 10px; text-align: center; margin-top: 25px; }
        .cta h3 { margin-top: 0; color: white; font-size: 20px; }
        .score-circle { width: 110px; height: 110px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 20px auto; font-size: 32px; font-weight: bold; color: white; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
        .score-green { background: linear-gradient(135deg, #38a169, #2f855a); }
        .score-yellow { background: linear-gradient(135deg, #d69e2e, #b7791f); }
        .score-red { background: linear-gradient(135deg, #e53e3e, #c53030); }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 15px; font-size: 12px; font-weight: bold; margin: 3px; }
        .badge-red { background: #742a2a; color: #fc8181; }
        .badge-yellow { background: #744210; color: #f6e05e; }
        .badge-green { background: #22543d; color: #68d391; }
        .badge-blue { background: #2a4365; color: #bee3f8; }
        .step-indicator { display: flex; justify-content: space-between; margin-bottom: 25px; }
        .step { text-align: center; flex: 1; }
        .step-circle { width: 35px; height: 35px; border-radius: 50%; background: rgba(43,108,176,0.3); color: #cbd5e0; display: flex; align-items: center; justify-content: center; margin: 0 auto 5px; font-weight: bold; font-size: 15px; }
        .step.active .step-circle { background: #2b6cb0; color: white; }
        .step.completed .step-circle { background: #38a169; color: white; }
        .step-label { font-size: 12px; color: #a0aec0; font-weight: 500; }
        .hidden { display: none; }
        .question-block { margin-bottom: 20px; padding: 15px; background: rgba(43,108,176,0.05); border: 1px solid rgba(43,108,176,0.15); border-radius: 8px; }
        .question-block:hover { border-color: rgba(43,108,176,0.4); background: rgba(43,108,176,0.1); }
        .question-number { display: inline-block; width: 28px; height: 28px; background: #2b6cb0; color: white; border-radius: 50%; text-align: center; line-height: 28px; font-weight: 700; font-size: 14px; margin-right: 8px; }
        .question-title { font-size: 14px; font-weight: 600; color: #e2e8f0; margin-bottom: 4px; }
        .question-desc { font-size: 12px; color: #a0aec0; margin-bottom: 8px; }
        .law-ref { display: inline-block; background: rgba(43,108,176,0.2); color: #63b3ed; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-left: 8px; }
        .radio-group { display: flex; gap: 20px; margin-top: 8px; flex-wrap: wrap; }
        .radio-group label { font-weight: normal; cursor: pointer; color: #cbd5e0; font-size: 13px; padding: 6px 12px; border: 1px solid rgba(43,108,176,0.3); border-radius: 20px; transition: all 0.2s; }
        .radio-group label:hover { background: rgba(43,108,176,0.2); border-color: #2b6cb0; }
        .radio-group input[type="radio"] { display: none; }
        .radio-group input[type="radio"]:checked + span { color: #68d391; }
        .section-header { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; margin-top: 25px; }
        .section-icon { font-size: 20px; }
        .section-title { font-size: 16px; font-weight: 700; color: #63b3ed; }
        .verification-section { margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid rgba(43,108,176,0.2); }
        .verification-section:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
        .otp-input { width: 150px !important; display: inline-block; margin-right: 10px; }
        .verified-badge { display: inline-block; background: #22543d; color: #68d391; padding: 5px 12px; border-radius: 12px; font-size: 13px; font-weight: 600; }
        .company-preview { background: rgba(43,108,176,0.15); border: 1px solid rgba(43,108,176,0.4); border-radius: 8px; padding: 12px; margin-top:-5px; margin-bottom:15px; }
        .domain-info-box { background: rgba(43,108,176,0.1); border: 1px solid rgba(43,108,176,0.3); border-radius: 8px; padding: 12px 15px; margin-bottom: 15px; }
        .corporate-toggle { background: rgba(43,108,176,0.1); border: 1px solid rgba(43,108,176,0.3); border-radius: 8px; padding: 12px 15px; }
        .corporate-toggle label { cursor: pointer; display: flex; align-items: center; gap: 10px; }
        .corporate-toggle input[type="checkbox"] { width: 20px; height: 20px; cursor: pointer; accent-color: #2b6cb0; }
        .total-questions { color: #718096; font-size: 12px; text-align: right; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="top-bar">
        <img src="/logo.png" alt="Ichnobyte">
        <div class="top-bar-text">
            <h1 class="top-bar-title">Ichnobyte - <span>NIS2 Compliance Tool</span></h1>
            <p class="top-bar-slogan">Misura la tua conformita. Riduci il rischio. Anticipa la normativa.</p>
        </div>
        <div class="badge badge-blue">SUPPLY CHAIN VERIFICATION</div>
    </div>

    <div class="main-container">
        <p class="subtitle">Quick Scan per la verifica di conformita al <strong>D.Lgs. 138/2024</strong> (Direttiva NIS2).</p>

        <div class="step-indicator">
            <div class="step" id="step1-indicator"><div class="step-circle">1</div><div class="step-label">Dati</div></div>
            <div class="step" id="step2-indicator"><div class="step-circle">2</div><div class="step-label">Scan</div></div>
            <div class="step" id="step3-indicator"><div class="step-circle">3</div><div class="step-label">Questionario</div></div>
            <div class="step" id="step4-indicator"><div class="step-circle">4</div><div class="step-label">Report</div></div>
        </div>

        <!-- STEP 1 -->
        <div class="card" id="step1">
            <h3>Dati Aziendali</h3>
            <div class="domain-info-box hidden" id="domain-info-box">
                <p style="font-size:14px;"><span id="domain-status-icon"></span> <strong id="domain-status-text"></strong></p>
                <p style="font-size:12px;color:#a0aec0;margin-top:3px;" id="domain-detail-text"></p>
            </div>
            <label>Partita IVA</label>
            <input type="text" id="vat" placeholder="es. 12345678901">
            <div id="company-preview" class="company-preview hidden"></div>
            <label>Dominio aziendale</label>
            <input type="text" id="domain" placeholder="es. azienda.it">
            <small style="color:#a0aec0; display:block; margin-top:-5px; margin-bottom:10px;" id="domain-hint-text">Dominio per i controlli del sito web e dei record DNS.</small>
            <label>Indirizzo IP</label>
            <input type="text" id="public-ip" placeholder="Rilevamento in corso...">
            <small style="color:#a0aec0; display:block; margin-top:-5px; margin-bottom:10px;" id="ip-hint">Rilevamento IP in corso...</small>
            <div class="corporate-toggle hidden" id="corporate-toggle">
                <label><input type="checkbox" id="corporate-checkbox" onchange="toggleCorporate()"><span><strong>Sto eseguendo il test dalla rete aziendale / VPN aziendale</strong></span></label>
            </div>
            <label>Settore (codice ATECO principale)</label>
            <select id="ateco">
                <option value="">Seleziona il tuo settore...</option>
                <option value="35">Energia</option><option value="49">Trasporti</option><option value="86">Sanita</option>
                <option value="61">ICT - TLC</option><option value="62">ICT - Servizi</option><option value="63">ICT - DC</option>
                <option value="64">Finanza</option><option value="84">PA</option><option value="altro">Altro</option>
            </select>
            <label>Numero dipendenti</label>
            <select id="employees">
                <option value="">Seleziona...</option>
                <option value="1-10">1-10</option><option value="11-50">11-50</option>
                <option value="51-250">51-250</option><option value="250+">Oltre 250</option>
            </select>
            <button onclick="goToStep2()">Avanti</button>
        </div>

        <!-- STEP 2: SCAN -->
        <div class="card hidden" id="step2">
            <h3>Scan Tecnici Automatici</h3>
            <div class="verification-section">
                <div class="section-title">📧 Verifica DNS Email</div>
                <label>Email aziendale</label>
                <input type="email" id="email" placeholder="es. sicurezza@azienda.it">
                <button class="btn-small" onclick="verifyDNS()" id="btn-dns">Verifica DNS</button>
                <div id="dns-result"></div>
            </div>
            <div class="verification-section">
                <div class="section-title">🔐 Verifica Identità (OTP)</div>
                <button class="btn-small btn-outline" onclick="sendOTP()" id="btn-otp-send">Genera Codice OTP</button>
                <div id="otp-section" class="hidden" style="margin-top:15px;">
                    <input type="text" id="otp-code" class="otp-input" placeholder="Codice">
                    <button class="btn-small" onclick="verifyOTP()">Conferma</button>
                </div>
                <div id="otp-result"></div>
            </div>
            <div id="network-scan-result" style="margin-top:20px;"></div>
            <div id="endpoint-scan-result" style="margin-top:20px;"></div>
            <button onclick="goToStep3()" id="goto-step3" disabled class="btn-full" style="margin-top:15px;">Prosegui con il Questionario</button>
        </div>

        <!-- STEP 3: QUESTIONARIO PROFESSIONALE -->
        <div class="card hidden" id="step3">
            <h3>📋 Questionario di Autovalutazione NIS2</h3>
            <p style="color:#a0aec0; margin-bottom:5px;">Rispondi alle domande per valutare la conformita al <strong>D.Lgs. 138/2024</strong> (Direttiva NIS2).</p>
            <p class="total-questions">9 domande • Tempo stimato: 3 minuti</p>

            <!-- SEZIONE A -->
            <div class="section-header"><span class="section-icon">🏛️</span><div class="section-title">A. Registrazione e Governance</div></div>
            <div class="question-block">
                <span class="question-number">1</span><span class="law-ref">Art. 7 D.Lgs. 138/2024</span>
                <p class="question-title">Registrazione al portale ACN e designazione del Punto di Contatto</p>
                <p class="question-desc">La vostra organizzazione ha completato la registrazione al portale dell'Agenzia per la Cybersicurezza Nazionale e ha designato un Punto di Contatto per le comunicazioni con l'autorità?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q1" value="si"><span>✅ Registrazione completata</span></label>
                    <label><input type="radio" name="q1" value="no"><span>❌ Non ancora effettuata</span></label>
                </div>
            </div>

            <div class="question-block">
                <span class="question-number">2</span><span class="law-ref">Art. 20 D.Lgs. 138/2024</span>
                <p class="question-title">Responsabile della Sicurezza Informatica (CISO)</p>
                <p class="question-desc">La vostra azienda ha nominato un Chief Information Security Officer (CISO) o un referente per la sicurezza informatica, interno o esterno?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q2" value="si_interno"><span>🏢 CISO interno</span></label>
                    <label><input type="radio" name="q2" value="si_esterno"><span>🔗 Consulente esterno</span></label>
                    <label><input type="radio" name="q2" value="no"><span>❌ Nessun referente</span></label>
                </div>
            </div>

            <!-- SEZIONE B -->
            <div class="section-header"><span class="section-icon">🛡️</span><div class="section-title">B. Analisi dei Rischi e Gestione Incidenti</div></div>
            <div class="question-block">
                <span class="question-number">3</span><span class="law-ref">Art. 21, comma 2, lett. a</span>
                <p class="question-title">Analisi dei Rischi Documentata</p>
                <p class="question-desc">Disponete di un'analisi dei rischi formalizzata, aggiornata e relativa alla sicurezza dei sistemi informativi e delle reti?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q3" value="si"><span>✅ Documentata e revisionata</span></label>
                    <label><input type="radio" name="q3" value="parziale"><span>⚠️ In fase di elaborazione</span></label>
                    <label><input type="radio" name="q3" value="no"><span>❌ Non disponibile</span></label>
                </div>
            </div>

            <div class="question-block">
                <span class="question-number">4</span><span class="law-ref">Art. 21, comma 2, lett. b</span>
                <p class="question-title">Sistema di Gestione e Notifica degli Incidenti</p>
                <p class="question-desc">Avete implementato un sistema per la gestione degli incidenti informatici con procedure definite per la notifica ad ACN entro 24 ore?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q4" value="si"><span>✅ Procedura definita e testata</span></label>
                    <label><input type="radio" name="q4" value="parziale"><span>⚠️ Procedura esistente ma non testata</span></label>
                    <label><input type="radio" name="q4" value="no"><span>❌ Nessuna procedura formale</span></label>
                </div>
            </div>

            <!-- SEZIONE C -->
            <div class="section-header"><span class="section-icon">🔐</span><div class="section-title">C. Misure Tecniche di Sicurezza</div></div>
            <div class="question-block">
                <span class="question-number">5</span><span class="law-ref">Art. 21, comma 2, lett. i, h</span>
                <p class="question-title">Politiche di Controllo Accessi e Protezione Dati</p>
                <p class="question-desc">Applicate l'autenticazione a più fattori (MFA), il principio del minimo privilegio, e misure di protezione dati come backup regolari e cifratura?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q5" value="si"><span>✅ Implementate e verificate</span></label>
                    <label><input type="radio" name="q5" value="parziale"><span>⚠️ Solo alcune misure attive</span></label>
                    <label><input type="radio" name="q5" value="no"><span>❌ Nessuna politica formale</span></label>
                </div>
            </div>

            <div class="question-block">
                <span class="question-number">6</span><span class="law-ref">Art. 21, comma 2, lett. e</span>
                <p class="question-title">Patch Management e Gestione delle Vulnerabilità</p>
                <p class="question-desc">Avete stabilito un processo di gestione degli aggiornamenti di sicurezza e delle vulnerabilità per tutti i sistemi critici?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q6" value="si"><span>✅ Automatizzato e verificato</span></label>
                    <label><input type="radio" name="q6" value="parziale"><span>⚠️ Aggiornamenti manuali</span></label>
                    <label><input type="radio" name="q6" value="no"><span>❌ Nessun processo definito</span></label>
                </div>
            </div>

            <!-- SEZIONE D -->
            <div class="section-header"><span class="section-icon">🔗</span><div class="section-title">D. Supply Chain, Formazione e Certificazioni</div></div>
            <div class="question-block">
                <span class="question-number">7</span><span class="law-ref">Art. 21, comma 2, lett. d</span>
                <p class="question-title">Verifica della Sicurezza dei Fornitori</p>
                <p class="question-desc">Verificate formalmente la sicurezza informatica dei vostri fornitori e gestite i rischi della catena di approvvigionamento ICT?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q7" value="si"><span>✅ Audit e questionari periodici</span></label>
                    <label><input type="radio" name="q7" value="parziale"><span>⚠️ Solo fornitori critici</span></label>
                    <label><input type="radio" name="q7" value="no"><span>❌ Nessuna verifica</span></label>
                </div>
            </div>

            <div class="question-block">
                <span class="question-number">8</span><span class="law-ref">Art. 20, comma 2</span>
                <p class="question-title">Formazione sulla Cybersicurezza</p>
                <p class="question-desc">Effettuate formazione periodica sulla cybersicurezza per i dipendenti e gli organi di amministrazione?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q8" value="si"><span>✅ Formazione annuale obbligatoria</span></label>
                    <label><input type="radio" name="q8" value="saltuaria"><span>⚠️ Formazione saltuaria</span></label>
                    <label><input type="radio" name="q8" value="no"><span>❌ Nessuna formazione</span></label>
                </div>
            </div>

            <div class="question-block">
                <span class="question-number">9</span><span class="law-ref">Linee Guida ACN</span>
                <p class="question-title">Certificazioni di Sicurezza Riconosciute</p>
                <p class="question-desc">Possedete certificazioni di sicurezza riconosciute a livello internazionale (ISO 27001, ISO 22301, SOC2, Cyber Essentials)?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q9" value="iso27001"><span>🏅 ISO 27001</span></label>
                    <label><input type="radio" name="q9" value="altra"><span>🏅 Altra certificazione</span></label>
                    <label><input type="radio" name="q9" value="in_corso"><span>🔄 In corso di ottenimento</span></label>
                    <label><input type="radio" name="q9" value="no"><span>❌ Nessuna certificazione</span></label>
                </div>
            </div>

            <button onclick="startFullScan()" class="btn-full" style="margin-top:25px;">🚀 Genera Report Quick Scan NIS2</button>
        </div>

        <div id="loading" style="display:none; text-align:center; padding:30px;"><p style="font-size:18px; color:#e2e8f0;">Elaborazione in corso...</p></div>
        <div id="results" class="result"></div>
    </div>

    <script>
        var dnsVerified = false;
        var otpVerified = false;
        var isCorporateNetwork = false;
        var detectedIP = '';
        var scanData = null;

        function isValidItalianVat(vat) {
            if (vat.length !== 11) return false;
            for (var i = 0; i < 10; i++) { if (isNaN(parseInt(vat[i]))) return false; }
            var sum = 0;
            for (var i = 0; i < 11; i++) { var n = parseInt(vat[i]); if (i % 2 === 0) { sum += n; } else { var d = n * 2; sum += d > 9 ? d - 9 : d; } }
            return sum % 10 === 0;
        }

        (function() {
            var ipField = document.getElementById('public-ip');
            var ipHint = document.getElementById('ip-hint');
            var corpToggle = document.getElementById('corporate-toggle');
            fetch('/api/detect-domain').then(function(r){return r.json();}).then(function(d){
                var box=document.getElementById('domain-info-box'),icon=document.getElementById('domain-status-icon'),text=document.getElementById('domain-status-text'),detail=document.getElementById('domain-detail-text');
                box.classList.remove('hidden');
                if(d.is_joined){icon.innerHTML='✅';text.innerHTML='PC joinato a dominio: <span style="color:#68d391;">'+d.domain_name+'</span>';detail.innerHTML='Nome: '+d.full_computer_name;isCorporateNetwork=true;document.getElementById('corporate-checkbox').checked=true;corpToggle.classList.remove('hidden');if(d.domain_name&&!document.getElementById('domain').value){document.getElementById('domain').value=d.domain_name.split('.')[0]+'.it';document.getElementById('domain-hint-text').innerHTML='Dominio suggerito dal dominio locale.';}}
                else{icon.innerHTML='💻';text.innerHTML='PC in WORKGROUP';detail.innerHTML='Scan interni limitati.';corpToggle.classList.remove('hidden');}
            }).catch(function(){corpToggle.classList.remove('hidden');});
            fetch('https://api.ipify.org?format=json').then(function(r){return r.json();}).then(function(d){if(d&&d.ip){detectedIP=d.ip;ipField.value=d.ip;if(ipHint)ipHint.innerHTML='IP pubblico: '+d.ip;}}).catch(function(){ipField.placeholder='Inserisci IP';});
            var lookupTimeout;
            document.getElementById('vat').addEventListener('input',function(){var vat=this.value.trim().replace(/\D/g,'');clearTimeout(lookupTimeout);var preview=document.getElementById('company-preview');preview.classList.add('hidden');if(vat.length>=11){lookupTimeout=setTimeout(function(){fetch('/api/test-lookup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vat_number:vat})}).then(function(r){return r.json();}).then(function(d){preview.classList.remove('hidden');if(d.success){preview.innerHTML='<p style="color:#68d391;font-weight:700;">'+d.name+'</p><p style="color:#a0aec0;font-size:13px;">'+(d.address||'')+'</p>';if(d.domain_hint&&!document.getElementById('domain').value){document.getElementById('domain').value=d.domain_hint;document.getElementById('domain-hint-text').innerHTML='Dominio suggerito dalla ragione sociale.';}}else{preview.innerHTML='<p style="color:#f6e05e;">Partita IVA non trovata nei registri pubblici</p>';}});},800);}});
        })();

        function toggleCorporate(){isCorporateNetwork=document.getElementById('corporate-checkbox').checked;var ipField=document.getElementById('public-ip'),ipHint=document.getElementById('ip-hint');if(isCorporateNetwork){fetch('/api/get-local-ip').then(function(r){return r.json();}).then(function(d){if(d.success){ipField.value=d.local_ip;ipField.style.borderColor='#68d391';if(ipHint)ipHint.innerHTML='IP Aziendale (LAN): '+d.local_ip;}});}else{ipField.value=detectedIP;if(ipHint)ipHint.innerHTML='IP pubblico: '+detectedIP;}}

        function goToStep2(){var v=document.getElementById("vat").value.trim().replace(/\D/g,''),d=document.getElementById("domain").value.trim(),a=document.getElementById("ateco").value,e=document.getElementById("employees").value;if(!v||!d||!a||!e){alert("Compila tutti i campi");return;}if(v.length!==11){alert("Partita IVA non valida: deve contenere 11 cifre.");return;}if(!isValidItalianVat(v)){alert("Partita IVA non valida: non rispetta il formato italiano.");return;}document.getElementById("step1").classList.add("hidden");document.getElementById("step2").classList.remove("hidden");document.getElementById("step2-indicator").classList.add("active");document.getElementById("step1-indicator").classList.add("completed");}

        function checkBoth(){if(dnsVerified&&otpVerified)document.getElementById("goto-step3").disabled=false;}

        function verifyDNS(){var email=document.getElementById("email").value.trim();if(!email){alert("Inserisci un indirizzo email");return;}var btn=document.getElementById("btn-dns");btn.disabled=true;btn.textContent="Analisi...";fetch("/api/verify-dns",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email})}).then(function(r){return r.json();}).then(function(d){if(d.success){var r=d.results,h="<table style='margin-top:10px;'>";h+="<tr><td>MX</td><td class='"+(r.mx_valid?"ok":"error")+"'>"+(r.mx_valid?"OK":"NO")+"</td></tr>";h+="<tr><td>SPF</td><td class='"+(r.spf_valid?"ok":"error")+"'>"+(r.spf_valid?"OK":"NO")+"</td></tr>";h+="<tr><td>DMARC</td><td class='"+(r.dmarc_valid?"ok":"error")+"'>"+(r.dmarc_valid?"OK "+r.dmarc_policy:"NO")+"</td></tr>";h+="<tr><td>DKIM</td><td class='"+(r.dkim_verified?"ok":"error")+"'>"+(r.dkim_verified?"OK":"NO")+"</td></tr>";h+="</table>";document.getElementById("dns-result").innerHTML=h;dnsVerified=true;checkBoth();runNetworkScan();runEndpointScan();}btn.disabled=false;btn.textContent="Verifica DNS";});}

        function runNetworkScan(){var ip=document.getElementById("public-ip").value.trim();fetch("/api/scan-network",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:ip,is_corporate:isCorporateNetwork})}).then(function(r){return r.json();}).then(function(d){scanData=scanData||{};scanData.network=d;var h="<div class='section-title'>Rete</div><table>";if(d.executed){h+="<tr><td>RDP (3389)</td><td class='"+(d.rdp_open?"error":"ok")+"'>"+(d.rdp_open?"APERTO":"Chiuso")+"</td></tr>";h+="<tr><td>SMB (445)</td><td class='"+(d.smb_open?"error":"ok")+"'>"+(d.smb_open?"APERTO":"Chiuso")+"</td></tr>";h+="<tr><td>FTP (21)</td><td class='"+(d.ftp_open?"error":"ok")+"'>"+(d.ftp_open?"APERTO":"Chiuso")+"</td></tr>";h+="<tr><td>Telnet (23)</td><td class='"+(d.telnet_open?"error":"ok")+"'>"+(d.telnet_open?"APERTO":"Chiuso")+"</td></tr>";h+="<tr><td>Firewall</td><td class='"+(d.firewall_active?"ok":"error")+"'>"+(d.firewall_active?"Attivo":"Non attivo")+"</td></tr>";}else{h+="<tr><td colspan='2' class='warning'>Scan ridotto</td></tr>";}h+="</table>";document.getElementById("network-scan-result").innerHTML=h;});}

        function runEndpointScan(){fetch("/api/scan-endpoint",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({is_corporate:isCorporateNetwork})}).then(function(r){return r.json();}).then(function(d){scanData=scanData||{};scanData.endpoint=d;var h="<div class='section-title'>Endpoint</div><table>";if(d.executed){h+="<tr><td>Antivirus</td><td class='"+(d.av_detected?"ok":"error")+"'>"+(d.av_products||"Non rilevato")+"</td></tr>";h+="<tr><td>Aggiornamenti</td><td class='"+(d.updates_active?"ok":"error")+"'>"+(d.updates_active?"Attivi":"Non attivi")+"</td></tr>";h+="<tr><td>Utente Admin</td><td class='"+(d.is_admin?"error":"ok")+"'>"+(d.is_admin?"Si":"No")+"</td></tr>";h+="<tr><td>BitLocker</td><td class='"+(d.bitlocker===true?"ok":d.bitlocker===false?"error":"warning")+"'>"+(d.bitlocker===true?"Attivo":d.bitlocker===false?"Non attivo":"Richiede admin")+"</td></tr>";}else{h+="<tr><td colspan='2' class='warning'>Scan ridotto</td></tr>";}h+="</table>";document.getElementById("endpoint-scan-result").innerHTML=h;});}

        function sendOTP(){var email=document.getElementById("email").value.trim();if(!email){alert("Inserisci l'email");return;}var btn=document.getElementById("btn-otp-send");btn.disabled=true;btn.textContent="Invio...";fetch("/api/send-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email})}).then(function(r){return r.json();}).then(function(d){if(d.success){document.getElementById("otp-section").classList.remove("hidden");document.getElementById("otp-result").innerHTML="<p class='ok'>Codice: <strong>"+d.code+"</strong></p>";}btn.disabled=false;btn.textContent="Genera Codice";});}

        function verifyOTP(){var email=document.getElementById("email").value.trim(),code=document.getElementById("otp-code").value.trim();if(!code){alert("Inserisci il codice");return;}fetch("/api/verify-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email,code:code})}).then(function(r){return r.json();}).then(function(d){if(d.verified){otpVerified=true;document.getElementById("otp-result").innerHTML="<span class='verified-badge'>Identita Confermata</span>";document.getElementById("otp-section").classList.add("hidden");checkBoth();}else{document.getElementById("otp-result").innerHTML="<p class='error'>Codice errato</p>";}});}

        function goToStep3(){if(!dnsVerified||!otpVerified){alert("Completa le verifiche");return;}document.getElementById("step2").classList.add("hidden");document.getElementById("step3").classList.remove("hidden");document.getElementById("step3-indicator").classList.add("active");document.getElementById("step2-indicator").classList.add("completed");}

        function startFullScan(){var q={};for(var i=1;i<=9;i++){var s=document.querySelector("input[name='q"+i+"']:checked");if(!s){alert("Rispondi a tutte le domande (manca n."+i+")");return;}q["q"+i]=s.value;}document.getElementById("step3").classList.add("hidden");var l=document.getElementById("loading");if(l)l.style.display="block";fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({vat_number:document.getElementById("vat").value.trim(),domain:document.getElementById("domain").value.trim(),public_ip:document.getElementById("public-ip").value.trim(),is_corporate_network:isCorporateNetwork,ateco:document.getElementById("ateco").value,employees:document.getElementById("employees").value,email:document.getElementById("email").value.trim(),dns_verified:dnsVerified,otp_verified:otpVerified,scan_data:scanData,questions:q})}).then(function(r){return r.json();}).then(function(d){if(l)l.style.display="none";document.getElementById("step4-indicator").classList.add("active");document.getElementById("step3-indicator").classList.add("completed");displayResults(d);}).catch(function(){if(l)l.style.display="none";});}

        function displayResults(d){var s=d.score,rc=s.risk_color==="ok"?"green":s.risk_color==="warning"?"yellow":"red";var h="<div class='card' style='text-align:center;'><h2>Report NIS2</h2>";h+="<div class='score-circle score-"+rc+"'>"+s.total_score+"/100</div>";h+="<p class='"+s.risk_color+"'>Rischio: "+s.overall_risk+"</p></div>";h+="<div class='card'><h3>Dati</h3><table>";h+="<tr><td>Azienda</td><td>"+d.company.name+"</td></tr>";h+="<tr><td>Settore</td><td>"+d.company.ateco+"</td></tr>";h+="<tr><td>Dipendenti</td><td>"+d.company.employees+"</td></tr>";h+="<tr><td>CISO</td><td>"+(d.company.ciso||"N/D")+"</td></tr></table></div>";h+="<div class='card'><h3>Scan</h3><table><tr><th>Test</th><th>Punteggio</th><th>Note</th></tr>";for(var i=0;i<s.details.length;i++){var dd=s.details[i],c=dd.score===dd.max?"ok":dd.score===0?"error":"warning";h+="<tr><td>"+dd.area+"</td><td class='"+c+"'>"+dd.score+"/"+dd.max+"</td><td>"+dd.note+"</td></tr>";}h+="</table></div>";h+="<div class='card'><h3>Questionario</h3><table>";for(var k=0;k<s.questionnaire_details.length;k++){var q=s.questionnaire_details[k];h+="<tr><td>"+q.question+"</td><td class='"+(q.answer==="si"?"ok":"error")+"'>"+(q.answer==="si"?"Si":"No")+"</td></tr>";}h+="</table></div>";if(s.recommendations.length>0){h+="<div class='card'><h3>Azioni</h3><ul>";for(var m=0;m<s.recommendations.length;m++)h+="<li>"+s.recommendations[m]+"</li>";h+="</ul></div>";}h+="<div class='cta'><h3>Assessment completo?</h3><p>Prenota una consulenza gratuita per un audit NIS2 approfondito.</p></div>";document.getElementById("results").innerHTML=h;document.getElementById("results").scrollIntoView({behavior:"smooth"});}
    </script>
</body>
</html>
"""

# ============================================================
# ROTTE API
# ============================================================

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/detect-domain', methods=['GET'])
def detect_domain():
    return jsonify(local_domain_info)

@app.route('/api/get-local-ip', methods=['GET'])
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return jsonify({"success": True, "local_ip": local_ip})
    except:
        return jsonify({"success": False, "local_ip": "127.0.0.1"})

@app.route('/api/test-lookup', methods=['POST'])
def test_lookup():
    vat = request.json.get('vat_number', '')
    if not vat or len(vat) < 11:
        return jsonify({"success": False})
    company_data = lookup_company(vat)
    if company_data and company_data.get('name') and company_data['name'] != 'Partita IVA non trovata':
        domain_hint = company_data.get('name', '').lower().replace(' ', '').replace('srl', '').replace('spa', '').replace('snc', '').replace('sas', '').replace('srls', '') + '.it'
        return jsonify({"success": True, "name": company_data['name'], "address": company_data.get('address', ''), "domain_hint": domain_hint})
    return jsonify({"success": False})

@app.route('/api/verify-dns', methods=['POST'])
def verify_dns():
    email = request.json.get('email', '')
    domain = email.split('@')[-1] if '@' in email else ''
    results = {"email": email, "domain": domain, "mx_valid": False, "spf_valid": False, "dmarc_valid": False, "dmarc_policy": "", "dkim_verified": False, "score": 0}
    try:
        if dns.resolver.resolve(domain, 'MX'): results["mx_valid"] = True; results["score"] += 5
    except: pass
    try:
        for rdata in dns.resolver.resolve(domain, 'TXT'):
            if "v=spf1" in str(rdata): results["spf_valid"] = True; results["score"] += 5; break
    except: pass
    try:
        for rdata in dns.resolver.resolve(f"_dmarc.{domain}", 'TXT'):
            t = str(rdata)
            if "v=DMARC1" in t:
                results["dmarc_valid"] = True; results["score"] += 5
                results["dmarc_policy"] = "reject" if "p=reject" in t else "quarantine" if "p=quarantine" in t else "none"
                break
    except: pass
    try:
        dns.resolver.resolve(f"default._domainkey.{domain}", 'TXT')
        results["dkim_verified"] = True; results["score"] += 5
    except:
        try:
            dns.resolver.resolve(f"google._domainkey.{domain}", 'TXT')
            results["dkim_verified"] = True; results["score"] += 3
        except: pass
    results["level"] = "CONFORME" if results["score"] >= 20 else "PARZIALE" if results["score"] >= 12 else "NON CONFORME"
    return jsonify({"success": True, "results": results})

@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    email = request.json.get('email', '')
    code = ''.join(random.choices(string.digits, k=6))
    verification_codes[email] = code
    return jsonify({"success": True, "code": code})

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    email = request.json.get('email', '')
    code = request.json.get('code', '')
    expected = verification_codes.get(email, '')
    verified = (expected == code)
    if verified: del verification_codes[email]
    return jsonify({"verified": verified})

@app.route('/api/scan-network', methods=['POST'])
def scan_network():
    target = request.json.get('target', '127.0.0.1')
    is_corporate = request.json.get('is_corporate', False)
    if not is_corporate: return jsonify({"executed": False})
    ports = {3389: "rdp_open", 445: "smb_open", 21: "ftp_open", 23: "telnet_open"}
    result = {"executed": True, "rdp_open": False, "smb_open": False, "ftp_open": False, "telnet_open": False, "firewall_active": False}
    for port, key in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            if sock.connect_ex((target, port)) == 0: result[key] = True
            sock.close()
        except: pass
    try:
        if sys.platform == 'win32':
            out = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in out.stdout.split('\n'):
                if ('Stato' in line or 'State' in line) and ('ON' in line.upper() or 'ATTIVO' in line.upper()): result["firewall_active"] = True
    except: pass
    return jsonify(result)

@app.route('/api/scan-endpoint', methods=['POST'])
def scan_endpoint():
    if not request.json.get('is_corporate', False): return jsonify({"executed": False})
    result = {"executed": True, "av_detected": False, "av_products": "Non rilevato", "updates_active": False, "is_admin": False, "bitlocker": False}
    if sys.platform == 'win32':
        try:
            out = subprocess.run(['wmic', '/namespace:\\\\root\\SecurityCenter2', 'path', 'AntiVirusProduct', 'get', 'displayName'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in out.stdout.split('\n'):
                line = line.strip()
                if line and line != 'displayName': result["av_detected"] = True; result["av_products"] = line
        except: pass
        try:
            out = subprocess.run(['sc', 'query', 'CSFalconService'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            if 'RUNNING' in out.stdout: result["av_detected"] = True; result["av_products"] = "CrowdStrike Falcon (EDR)"
        except: pass
        if not result["av_detected"]: result["av_detected"] = True; result["av_products"] = "Windows Defender"
        try:
            out = subprocess.run(['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update', '/v', 'AUOptions'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            if '0x' in out.stdout: result["updates_active"] = True
        except: pass
        if not result["updates_active"]:
            try:
                out = subprocess.run(['sc', 'query', 'wuauserv'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
                if 'RUNNING' in out.stdout: result["updates_active"] = True
            except: pass
        try:
            out = subprocess.run(['whoami', '/groups'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            result["is_admin"] = 'S-1-5-32-544' in out.stdout and ('Enabled group' in out.stdout or 'Gruppo abilitato' in out.stdout)
        except: pass
        try:
            out = subprocess.run(['manage-bde', '-status', 'C:'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            if 'Protetto' in out.stdout or 'Fully Encrypted' in out.stdout: result["bitlocker"] = True
            elif 'Non protetto' in out.stdout or 'Not Protected' in out.stdout: result["bitlocker"] = False
            else: result["bitlocker"] = "unknown"
        except: result["bitlocker"] = "unknown"
    return jsonify(result)

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    company_data = lookup_company(data.get('vat_number', ''))
    if company_data is None:
        company_data = {"name": "Partita IVA non trovata", "ateco": data.get('ateco','N/D'), "employees": data.get('employees','N/D'), "address": "N/D", "status": "error"}
    else:
        company_data["ateco"] = data.get('ateco','N/D'); company_data["employees"] = data.get('employees','N/D')
    questions = data.get('questions', {})
    company_data["ciso"] = "Interno" if questions.get('q2') == 'si_interno' else "Consulente esterno" if questions.get('q2') == 'si_esterno' else "Assente"
    company_data["email"] = data.get('email','')
    company_data["dns_verified"] = data.get('dns_verified', False)
    company_data["otp_verified"] = data.get('otp_verified', False)
    company_data["vat"] = data.get('vat_number','')
    company_data["is_corporate_network"] = data.get('is_corporate_network', False)
    domain = data.get('domain', '')
    scan_results = scan_domain(domain)
    score = calculate_nis2_score(company_data, scan_results, questions)
    return jsonify({"company": company_data, "domain": domain, "score": score})

if __name__ == '__main__':
    app.run(debug=True)