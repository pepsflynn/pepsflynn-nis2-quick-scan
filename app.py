from flask import Flask, render_template_string, request, jsonify
from company_lookup import lookup_company
from domain_scanner import scan_domain
from scoring import calculate_nis2_score
import random
import string
import dns.resolver
import os

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = 'nis2-web-version-2026'

verification_codes = {}

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
            display: flex; align-items: center; justify-content: space-between;
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
        .btn-download {
            background: linear-gradient(135deg, #38a169, #2f855a);
            color: white; border: none; padding: 16px 30px;
            border-radius: 10px; cursor: pointer; font-size: 16px; font-weight: 700;
            display: inline-block; text-decoration: none; text-align: center;
            transition: transform 0.2s; width: 100%;
        }
        .btn-download:hover { transform: scale(1.02); }
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
        .download-box {
            background: rgba(56, 161, 105, 0.1); border: 2px solid rgba(56, 161, 105, 0.4);
            border-radius: 12px; padding: 30px; text-align: center; margin-top: 25px;
        }
        .download-box h3 { color: #68d391; font-size: 22px; margin-bottom: 15px; }
        .download-box p { color: #a0aec0; margin-bottom: 20px; font-size: 15px; }
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
        .cloud-info-box { background: rgba(43,108,176,0.1); border: 1px solid rgba(43,108,176,0.3); border-radius: 8px; padding: 12px 15px; margin-bottom: 15px; }
        .total-questions { color: #718096; font-size: 12px; text-align: right; margin-bottom: 10px; }
        .features-list { list-style: none; padding: 0; margin: 15px 0; text-align: left; display: inline-block; }
        .features-list li { padding: 8px 0; color: #cbd5e0; font-size: 14px; }
        .features-list li span { margin-right: 10px; }
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
        <p class="subtitle">Quick Scan gratuito per la verifica di conformita al <strong>D.Lgs. 138/2024</strong> (Direttiva NIS2).</p>

        <div class="cloud-info-box">
            <p style="font-size:13px;"><strong>☁️ Versione Cloud - Analisi della superficie pubblica</strong></p>
            <p style="font-size:12px;color:#a0aec0;">Questa versione web esegue <strong style="color:#63b3ed;">11 controlli automatici</strong>: SSL/TLS, header sicurezza, WAF, CMS, DMARC, SPF, DNSSEC, redirect HTTPS, file sensibili esposti, versione TLS e subdomain takeover. Per l'analisi della rete interna scarica la versione portable.</p>
        </div>

        <div class="step-indicator">
            <div class="step" id="step1-indicator"><div class="step-circle">1</div><div class="step-label">Dati</div></div>
            <div class="step" id="step2-indicator"><div class="step-circle">2</div><div class="step-label">Scan</div></div>
            <div class="step" id="step3-indicator"><div class="step-circle">3</div><div class="step-label">Questionario</div></div>
            <div class="step" id="step4-indicator"><div class="step-circle">4</div><div class="step-label">Report</div></div>
        </div>

        <!-- STEP 1 -->
        <div class="card" id="step1">
            <h3>Dati Aziendali</h3>
            <label>Partita IVA</label>
            <input type="text" id="vat" placeholder="es. 12345678901">
            <div id="company-preview" class="company-preview hidden"></div>
            <label>Dominio aziendale</label>
            <input type="text" id="domain" placeholder="es. azienda.it">
            <small style="color:#a0aec0; display:block; margin-top:-5px; margin-bottom:10px;">Dominio per i controlli del sito web e dei record DNS.</small>
            <label>Settore (codice ATECO principale)</label>
            <select id="ateco">
                <option value="">Seleziona il tuo settore...</option>
                <option value="35">Energia</option><option value="49">Trasporti</option><option value="86">Sanita</option>
                <option value="61">ICT - TLC</option><option value="62">ICT - Servizi</option><option value="63">ICT - DC</option>
                <option value="64">Finanza</option><option value="84">PA</option><option value="altro">Altro</option>
            </select>
            <div id="ateco-hint" style="display:none; font-size:12px; margin-top:-6px; margin-bottom:10px; padding:8px 10px; border-radius:6px;"></div>
            <label>Numero dipendenti</label>
            <select id="employees">
                <option value="">Seleziona...</option>
                <option value="1-10">1-10</option><option value="11-50">11-50</option>
                <option value="51-250">51-250</option><option value="250+">Oltre 250</option>
            </select>
            <div id="employees-hint" style="display:none; font-size:12px; margin-top:-6px; margin-bottom:10px; padding:8px 10px; border-radius:6px;"></div>
            <button onclick="goToStep2()">Avanti</button>
        </div>

        <!-- STEP 2: SCAN WEB -->
        <div class="card hidden" id="step2">
            <h3>Scan Tecnici - Versione Cloud</h3>
            <p style="color:#a0aec0; margin-bottom:10px; font-size:13px;">☁️ Verifica e conferma la tua identità per avviare i <strong>11 controlli automatici</strong> sul dominio.</p>
            <div style="background:rgba(56,161,105,0.08);border:1px solid rgba(56,161,105,0.3);border-radius:8px;padding:10px 14px;margin-bottom:15px;font-size:12px;color:#a0aec0;line-height:1.7;">
                <strong style="color:#68d391;">✅ Inclusi in questa versione cloud:</strong><br>
                SSL/TLS &amp; versione protocollo • Header sicurezza HTTP • Redirect HTTPS •
                WAF • CMS e tecnologie • File sensibili esposti • DMARC • SPF • DNSSEC • Subdomain takeover
            </div>
            
            <div class="verification-section">
                <div class="section-title">📧 Verifica DNS Email</div>
                <label>Email aziendale</label>
                <input type="email" id="email" placeholder="es. sicurezza@azienda.it" oninput="checkEmailDomain()">
                <div id="email-domain-warning" style="display:none;font-size:12px;padding:7px 10px;border-radius:6px;margin:4px 0 6px;"></div>
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
            
            <div style="background:rgba(43,108,176,0.1);border:1px solid rgba(43,108,176,0.3);border-radius:8px;padding:12px;margin-top:15px;">
                <p style="font-size:13px;color:#63b3ed;"><strong>🏢 Rete interna — solo versione portable</strong></p>
                <p style="font-size:12px;color:#a0aec0;">RDP, SMB, firewall, antivirus, BitLocker, porte interne e crittografia endpoint richiedono la <strong>versione portable</strong> da eseguire sulla rete aziendale.</p>
            </div>

            <button onclick="goToStep3()" id="goto-step3" disabled class="btn-full" style="margin-top:15px;">Prosegui con il Questionario</button>
        </div>

        <!-- STEP 3: QUESTIONARIO -->
        <div class="card hidden" id="step3">
            <h3>📋 Questionario di Autovalutazione NIS2</h3>
            <p style="color:#a0aec0; margin-bottom:5px;">Rispondi alle domande per valutare la conformita al <strong>D.Lgs. 138/2024</strong>.</p>
            <p class="total-questions">9 domande • Tempo stimato: 3 minuti</p>

            <div class="section-header"><span class="section-icon">🏛️</span><div class="section-title">A. Registrazione e Governance</div></div>
            <div class="question-block">
                <span class="question-number">1</span><span class="law-ref">Art. 7 D.Lgs. 138/2024</span>
                <p class="question-title">Registrazione al portale ACN e designazione del Punto di Contatto</p>
                <p class="question-desc">La vostra organizzazione ha completato la registrazione e ha designato un Punto di Contatto?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q1" value="si"><span>✅ Completata</span></label>
                    <label><input type="radio" name="q1" value="no"><span>❌ Non ancora</span></label>
                </div>
            </div>
            <div class="question-block">
                <span class="question-number">2</span><span class="law-ref">Art. 20 D.Lgs. 138/2024</span>
                <p class="question-title">Responsabile della Sicurezza Informatica (CISO)</p>
                <p class="question-desc">Avete nominato un CISO o referente per la sicurezza, interno o esterno?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q2" value="si_interno"><span>🏢 CISO interno</span></label>
                    <label><input type="radio" name="q2" value="si_esterno"><span>🔗 Consulente esterno</span></label>
                    <label><input type="radio" name="q2" value="no"><span>❌ Nessuno</span></label>
                </div>
            </div>

            <div class="section-header"><span class="section-icon">🛡️</span><div class="section-title">B. Analisi dei Rischi e Gestione Incidenti</div></div>
            <div class="question-block">
                <span class="question-number">3</span><span class="law-ref">Art. 21, comma 2, lett. a</span>
                <p class="question-title">Analisi dei Rischi Documentata</p>
                <p class="question-desc">Disponete di un'analisi dei rischi formalizzata e aggiornata?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q3" value="si"><span>✅ Sì</span></label>
                    <label><input type="radio" name="q3" value="parziale"><span>⚠️ In elaborazione</span></label>
                    <label><input type="radio" name="q3" value="no"><span>❌ No</span></label>
                </div>
            </div>
            <div class="question-block">
                <span class="question-number">4</span><span class="law-ref">Art. 21, comma 2, lett. b</span>
                <p class="question-title">Gestione e Notifica degli Incidenti</p>
                <p class="question-desc">Avete un sistema di notifica incidenti ad ACN entro 24 ore?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q4" value="si"><span>✅ Testato</span></label>
                    <label><input type="radio" name="q4" value="parziale"><span>⚠️ Non testato</span></label>
                    <label><input type="radio" name="q4" value="no"><span>❌ No</span></label>
                </div>
            </div>

            <div class="section-header"><span class="section-icon">🔐</span><div class="section-title">C. Misure Tecniche di Sicurezza</div></div>
            <div class="question-block">
                <span class="question-number">5</span><span class="law-ref">Art. 21, comma 2, lett. i, h</span>
                <p class="question-title">Politiche di Accesso e Protezione Dati (MFA, backup, cifratura)</p>
                <p class="question-desc">Applicate MFA, minimo privilegio, backup regolari e cifratura?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q5" value="si"><span>✅ Implementate</span></label>
                    <label><input type="radio" name="q5" value="parziale"><span>⚠️ Parziali</span></label>
                    <label><input type="radio" name="q5" value="no"><span>❌ No</span></label>
                </div>
            </div>
            <div class="question-block">
                <span class="question-number">6</span><span class="law-ref">Art. 21, comma 2, lett. e</span>
                <p class="question-title">Patch Management e Gestione Vulnerabilità</p>
                <p class="question-desc">Avete un processo di aggiornamento sicurezza per tutti i sistemi critici?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q6" value="si"><span>✅ Automatizzato</span></label>
                    <label><input type="radio" name="q6" value="parziale"><span>⚠️ Manuale</span></label>
                    <label><input type="radio" name="q6" value="no"><span>❌ No</span></label>
                </div>
            </div>

            <div class="section-header"><span class="section-icon">🔗</span><div class="section-title">D. Supply Chain, Formazione e Certificazioni</div></div>
            <div class="question-block">
                <span class="question-number">7</span><span class="law-ref">Art. 21, comma 2, lett. d</span>
                <p class="question-title">Verifica della Sicurezza dei Fornitori</p>
                <p class="question-desc">Verificate la sicurezza informatica dei vostri fornitori?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q7" value="si"><span>✅ Audit periodici</span></label>
                    <label><input type="radio" name="q7" value="parziale"><span>⚠️ Solo critici</span></label>
                    <label><input type="radio" name="q7" value="no"><span>❌ No</span></label>
                </div>
            </div>
            <div class="question-block">
                <span class="question-number">8</span><span class="law-ref">Art. 20, comma 2</span>
                <p class="question-title">Formazione sulla Cybersicurezza</p>
                <p class="question-desc">Effettuate formazione periodica per dipendenti e amministratori?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q8" value="si"><span>✅ Annuale</span></label>
                    <label><input type="radio" name="q8" value="saltuaria"><span>⚠️ Saltuaria</span></label>
                    <label><input type="radio" name="q8" value="no"><span>❌ No</span></label>
                </div>
            </div>
            <div class="question-block">
                <span class="question-number">9</span><span class="law-ref">Linee Guida ACN</span>
                <p class="question-title">Certificazioni di Sicurezza</p>
                <p class="question-desc">Possedete certificazioni riconosciute (ISO 27001, SOC2, etc.)?</p>
                <div class="radio-group">
                    <label><input type="radio" name="q9" value="iso27001"><span>🏅 ISO 27001</span></label>
                    <label><input type="radio" name="q9" value="altra"><span>🏅 Altra</span></label>
                    <label><input type="radio" name="q9" value="in_corso"><span>🔄 In corso</span></label>
                    <label><input type="radio" name="q9" value="no"><span>❌ Nessuna</span></label>
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

        function isValidItalianVat(vat) {
            if (vat.length !== 11) return false;
            for (var i = 0; i < 10; i++) { if (isNaN(parseInt(vat[i]))) return false; }
            var sum = 0;
            for (var i = 0; i < 11; i++) { var n = parseInt(vat[i]); if (i % 2 === 0) { sum += n; } else { var d = n * 2; sum += d > 9 ? d - 9 : d; } }
            return sum % 10 === 0;
        }

        (function() {
            var lookupTimeout;
            document.getElementById('vat').addEventListener('input', function() {
                var vat = this.value.trim().replace(/\D/g, '');
                clearTimeout(lookupTimeout);
                var preview = document.getElementById('company-preview');
                preview.classList.add('hidden');
                if (vat.length >= 11) {
                    lookupTimeout = setTimeout(function() {
                        fetch('/api/test-lookup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({vat_number: vat}) })
                            .then(function(r) { return r.json(); })
                            .then(function(d) {
                                preview.classList.remove('hidden');
                                if (d.success) {
                                    preview.innerHTML = '<p style="color:#68d391;font-weight:700;">' + d.name + '</p><p style="color:#a0aec0;font-size:13px;">' + (d.address||'') + '</p>';
                                    var domainField = document.getElementById('domain');
                                    if (d.domain_hint && !domainField.value) {
                                        domainField.value = '';
                                        domainField.placeholder = 'Ricerca dominio in corso...';
                                        domainField.disabled = true;
                                        setTimeout(function() {
                                            domainField.value = d.domain_hint;
                                            domainField.placeholder = 'es. azienda.it';
                                            domainField.disabled = false;
                                        }, 300);
                                    }
                                    var atecoResult = d.ateco ? autoSelectAteco(d.ateco) : false;
                                    var empOk = (d.employees_count !== null && d.employees_count !== undefined) ? autoSelectEmployees(d.employees_count) : false;
                                    if (atecoResult && atecoResult.found) {
                                        showFieldHint('ateco-hint', true,
                                            '✅ Settore ATECO rilevato: <strong>' + atecoResult.code + '</strong> — ' + atecoResult.label,
                                            '');
                                    } else if (atecoResult && atecoResult.code) {
                                        showFieldHint('ateco-hint', false, '',
                                            '⚠️ Codice ATECO rilevato (<strong>' + atecoResult.code + '</strong>) non rientra nelle categorie NIS2 — seleziona il settore manualmente.');
                                    } else {
                                        showFieldHint('ateco-hint', false, '',
                                            '⚠️ Codice ATECO non disponibile nei registri pubblici — seleziona il settore manualmente.');
                                    }
                                    showFieldHint('employees-hint', empOk,
                                        '✅ Numero dipendenti rilevato automaticamente: <strong>' + d.employees_count + '</strong>.',
                                        '⚠️ Numero dipendenti non disponibile nei registri pubblici — selezionalo manualmente.');
                                } else {
                                    preview.innerHTML = '<p style="color:#f6e05e;">Partita IVA non trovata nei registri pubblici</p>';
                                }
                            });
                    }, 800);
                }
            });
        })();

        function goToStep2() {
            var v = document.getElementById("vat").value.trim().replace(/\D/g,''), d = document.getElementById("domain").value.trim(),
                a = document.getElementById("ateco").value, e = document.getElementById("employees").value;
            if (!v || !d || !a || !e) { alert("Compila tutti i campi"); return; }
            if (v.length !== 11) { alert("Partita IVA non valida: deve contenere 11 cifre."); return; }
            if (!isValidItalianVat(v)) { alert("Partita IVA non valida: non rispetta il formato italiano."); return; }
            document.getElementById("step1").classList.add("hidden");
            document.getElementById("step2").classList.remove("hidden");
            document.getElementById("step2-indicator").classList.add("active");
            document.getElementById("step1-indicator").classList.add("completed");
        }

        function showFieldHint(id, ok, okMsg, failMsg) {
            var el = document.getElementById(id);
            if (!el) return;
            el.style.display = 'block';
            if (ok) {
                el.style.background = 'rgba(56,161,105,0.12)';
                el.style.border = '1px solid rgba(56,161,105,0.4)';
                el.style.color = '#68d391';
                el.innerHTML = okMsg;
            } else {
                el.style.background = 'rgba(246,224,94,0.08)';
                el.style.border = '1px solid rgba(246,224,94,0.35)';
                el.style.color = '#f6e05e';
                el.innerHTML = failMsg;
            }
        }

        var ATECO_MAP = [
            { prefix: '35', value: '35', label: 'Energia' },
            { prefix: '49', value: '49', label: 'Trasporti' },
            { prefix: '50', value: '49', label: 'Trasporti' },
            { prefix: '51', value: '49', label: 'Trasporti' },
            { prefix: '52', value: '49', label: 'Trasporti' },
            { prefix: '53', value: '49', label: 'Trasporti' },
            { prefix: '86', value: '86', label: 'Sanità' },
            { prefix: '87', value: '86', label: 'Sanità' },
            { prefix: '88', value: '86', label: 'Sanità' },
            { prefix: '61', value: '61', label: 'ICT - TLC' },
            { prefix: '62', value: '62', label: 'ICT - Servizi' },
            { prefix: '63', value: '63', label: 'ICT - DC' },
            { prefix: '64', value: '64', label: 'Finanza' },
            { prefix: '65', value: '64', label: 'Finanza' },
            { prefix: '66', value: '64', label: 'Finanza' },
            { prefix: '84', value: '84', label: 'PA' }
        ];

        function autoSelectAteco(code) {
            if (!code) return false;
            var clean = code.replace(/\./g, '');
            var sel = document.getElementById('ateco');
            if (sel.value) return { found: true, code: code, label: sel.options[sel.selectedIndex].text };
            for (var i = 0; i < ATECO_MAP.length; i++) {
                if (clean.startsWith(ATECO_MAP[i].prefix)) {
                    sel.value = ATECO_MAP[i].value;
                    sel.style.borderColor = '#68d391';
                    setTimeout(function() { sel.style.borderColor = ''; }, 2000);
                    return { found: true, code: code, label: ATECO_MAP[i].label };
                }
            }
            // Codice presente ma non mappato nelle categorie NIS2: non auto-selezionare
            return { found: false, code: code, label: '' };
        }

        function autoSelectEmployees(count) {
            if (count === null || count === undefined) return false;
            var n = parseInt(count);
            if (isNaN(n)) return false;
            var sel = document.getElementById('employees');
            if (sel.value) return true; // già compilato, considera ok
            if (n <= 10)       sel.value = '1-10';
            else if (n <= 50)  sel.value = '11-50';
            else if (n <= 250) sel.value = '51-250';
            else               sel.value = '250+';
            sel.style.borderColor = '#68d391';
            setTimeout(function() { sel.style.borderColor = ''; }, 2000);
            return true;
        }

        function checkBoth() { if (dnsVerified && otpVerified) document.getElementById("goto-step3").disabled = false; }

        function checkEmailDomain() {
            var email = document.getElementById("email").value.trim();
            var siteDomain = document.getElementById("domain").value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
            var warn = document.getElementById("email-domain-warning");
            if (!email || !siteDomain || email.indexOf('@') < 0) { warn.style.display = 'none'; return; }
            var emailDomain = email.split('@')[1] || '';
            // considera match anche se il dominio email è un sottodominio del dominio sito o viceversa
            var match = emailDomain === siteDomain ||
                        emailDomain.endsWith('.' + siteDomain) ||
                        siteDomain.endsWith('.' + emailDomain);
            if (!match) {
                warn.style.display = 'block';
                warn.style.background = 'rgba(246,224,94,0.1)';
                warn.style.border = '1px solid rgba(246,224,94,0.4)';
                warn.style.color = '#f6e05e';
                warn.innerHTML = '⚠️ Il dominio email (<strong>' + emailDomain + '</strong>) è diverso dal dominio aziendale (<strong>' + siteDomain + '</strong>). I risultati DNS si riferiranno al dominio email.';
            } else {
                warn.style.display = 'block';
                warn.style.background = 'rgba(56,161,105,0.1)';
                warn.style.border = '1px solid rgba(56,161,105,0.3)';
                warn.style.color = '#68d391';
                warn.innerHTML = '✅ Dominio email coerente con il dominio aziendale.';
            }
        }

        function verifyDNS() {
            var email = document.getElementById("email").value.trim();
            if (!email) { alert("Inserisci un indirizzo email"); return; }
            checkEmailDomain();
            var btn = document.getElementById("btn-dns");
            btn.disabled = true; btn.textContent = "Analisi DNS...";
            fetch("/api/verify-dns", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: email}) })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success) {
                    var r = d.results;
                    var levelColor = r.level === "CONFORME" ? "#68d391" : r.level === "PARZIALE" ? "#f6e05e" : "#fc8181";
                    var h = "<div style='margin:10px 0 8px;padding:8px 12px;border-radius:6px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);font-size:13px;'>";
                    h += "Dominio analizzato: <strong>" + r.domain + "</strong> &nbsp;|&nbsp; ";
                    h += "Livello: <strong style='color:" + levelColor + ";'>" + r.level + "</strong>";
                    h += " &nbsp;(" + r.score + " pt)</div>";
                    h += "<table style='margin-top:4px;font-size:13px;'>";

                    // MX
                    h += "<tr><td><strong>MX</strong> &mdash; server di posta</td>";
                    h += "<td class='" + (r.mx_valid?"ok":"error") + "'>" + (r.mx_valid ? "✅ OK (" + r.mx_count + " record)" : "❌ Assente") + "</td></tr>";

                    // SPF
                    var spfClass = !r.spf_valid ? "error" : r.spf_strict ? "ok" : "warning";
                    var spfLabel = !r.spf_valid ? "❌ Assente" : (r.spf_strict ? "✅ OK (strict -all)" : "⚠️ Presente (~all, permissivo)");
                    h += "<tr><td><strong>SPF</strong> &mdash; mittenti autorizzati</td><td class='" + spfClass + "'>" + spfLabel + "</td></tr>";

                    // DMARC
                    var dmarcClass = !r.dmarc_valid ? "error" : r.dmarc_policy === "reject" ? "ok" : r.dmarc_policy === "quarantine" ? "warning" : "warning";
                    var dmarcLabel = !r.dmarc_valid ? "❌ Assente" :
                        "✅ policy: <strong>" + r.dmarc_policy + "</strong>" + (r.dmarc_rua ? " + reporting" : " (no reporting)");
                    if (r.dmarc_policy === "reject") dmarcLabel = "✅ " + dmarcLabel.replace("✅ ","");
                    else if (r.dmarc_valid && r.dmarc_policy !== "reject") dmarcLabel = "⚠️ policy: <strong>" + r.dmarc_policy + "</strong>" + (r.dmarc_rua ? " + reporting" : "");
                    h += "<tr><td><strong>DMARC</strong> &mdash; anti-spoofing</td><td class='" + dmarcClass + "'>" + dmarcLabel + "</td></tr>";

                    // DKIM
                    var dkimLabel = r.dkim_verified
                        ? "✅ OK (selettore: <em>" + r.dkim_selector + "</em>)"
                        : "❌ Non rilevato (selettori comuni verificati)";
                    h += "<tr><td><strong>DKIM</strong> &mdash; firma digitale</td><td class='" + (r.dkim_verified?"ok":"error") + "'>" + dkimLabel + "</td></tr>";

                    // MTA-STS
                    h += "<tr><td><strong>MTA-STS</strong> &mdash; cifratura SMTP</td>";
                    h += "<td class='" + (r.mta_sts?"ok":"warning") + "'>" + (r.mta_sts ? "✅ Abilitato" : "⚠️ Non configurato") + "</td></tr>";

                    h += "</table>";
                    document.getElementById("dns-result").innerHTML = h;
                    dnsVerified = true; checkBoth();
                }
                btn.disabled = false; btn.textContent = "Verifica DNS";
            });
        }

        function sendOTP() {
            var email = document.getElementById("email").value.trim();
            if (!email) { alert("Inserisci l'email"); return; }
            var btn = document.getElementById("btn-otp-send");
            btn.disabled = true; btn.textContent = "Invio...";
            fetch("/api/send-otp", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: email}) })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success) {
                    document.getElementById("otp-section").classList.remove("hidden");
                    document.getElementById("otp-result").innerHTML = "<p class='ok'>Codice: <strong>" + d.code + "</strong></p>";
                }
                btn.disabled = false; btn.textContent = "Genera Codice";
            });
        }

        function verifyOTP() {
            var email = document.getElementById("email").value.trim(), code = document.getElementById("otp-code").value.trim();
            if (!code) { alert("Inserisci il codice"); return; }
            fetch("/api/verify-otp", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: email, code: code}) })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.verified) {
                    otpVerified = true;
                    document.getElementById("otp-result").innerHTML = "<span class='verified-badge'>Identita Confermata</span>";
                    document.getElementById("otp-section").classList.add("hidden");
                    checkBoth();
                } else { document.getElementById("otp-result").innerHTML = "<p class='error'>Codice errato</p>"; }
            });
        }

        function goToStep3() {
            if (!dnsVerified || !otpVerified) { alert("Completa le verifiche"); return; }
            document.getElementById("step2").classList.add("hidden");
            document.getElementById("step3").classList.remove("hidden");
            document.getElementById("step3-indicator").classList.add("active");
            document.getElementById("step2-indicator").classList.add("completed");
        }

        function startFullScan() {
            var q = {};
            for (var i = 1; i <= 9; i++) {
                var s = document.querySelector("input[name='q"+i+"']:checked");
                if (!s) { alert("Rispondi a tutte le domande (manca n." + i + ")"); return; }
                q["q"+i] = s.value;
            }
            document.getElementById("step3").classList.add("hidden");
            var l = document.getElementById("loading"); if (l) l.style.display = "block";
            fetch("/api/scan", {
                method: "POST", headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    vat_number: document.getElementById("vat").value.trim(),
                    domain: document.getElementById("domain").value.trim(),
                    ateco: document.getElementById("ateco").value,
                    employees: document.getElementById("employees").value,
                    email: document.getElementById("email").value.trim(),
                    dns_verified: dnsVerified, otp_verified: otpVerified,
                    questions: q
                })
            })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (l) l.style.display = "none";
                document.getElementById("step4-indicator").classList.add("active");
                document.getElementById("step3-indicator").classList.add("completed");
                displayResults(d);
            })
            .catch(function() { if (l) l.style.display = "none"; });
        }

        function displayResults(d) {
            var s = d.score, rc = s.risk_color === "ok" ? "green" : s.risk_color === "warning" ? "yellow" : "red";

            // ---- HEADER REPORT ----
            var h = "<div class='card' style='text-align:center;'><h2>Report Quick Scan NIS2</h2>";
            h += "<div class='score-circle score-" + rc + "'>" + s.total_score + "/100</div>";
            h += "<p class='" + s.risk_color + "' style='font-size:18px;margin:5px 0;'>Rischio: <strong>" + s.overall_risk + "</strong></p>";
            if (s.nis2_category) {
                var catColor = s.nis2_category.category === "Essenziale" ? "#fc8181" : s.nis2_category.category === "Importante" ? "#f6e05e" : "#63b3ed";
                h += "<p style='font-size:13px;margin:4px 0;'>Categoria NIS2: <strong style='color:" + catColor + ";'>" + s.nis2_category.category + "</strong> &mdash; " + s.nis2_category.description + "</p>";
            }
            h += "<p style='font-size:11px;color:#718096;margin-top:8px;'>☁️ Versione Cloud &mdash; 11 controlli automatici sul dominio pubblico</p></div>";

            // ---- DATI AZIENDA ----
            h += "<div class='card'><h3>Dati Aziendali</h3><table>";
            h += "<tr><td>Azienda</td><td><strong>" + d.company.name + "</strong></td></tr>";
            h += "<tr><td>Settore ATECO</td><td>" + d.company.ateco + "</td></tr>";
            h += "<tr><td>Dipendenti</td><td>" + d.company.employees + "</td></tr>";
            h += "<tr><td>Responsabile sicurezza</td><td>" + (d.company.ciso || "N/D") + "</td></tr>";
            h += "<tr><td>Dominio analizzato</td><td>" + d.domain + "</td></tr></table></div>";

            // ---- SCAN TECNICI raggruppati ----
            var groups = [
                { label: "🌐 Sito web", keys: ["SSL", "Header", "CMS", "WAF", "HTTP", "File", "TLS", "Subdomain"] },
                { label: "📧 Email / DNS",  keys: ["DMARC", "SPF", "DNSSEC"] }
            ];
            h += "<div class='card'><h3>Scan Tecnici Automatici</h3>";

            // calcola totale tecnico
            var techTotal = 0, techMax = 0;
            for (var i = 0; i < s.details.length; i++) { techTotal += s.details[i].score; techMax += s.details[i].max; }
            h += "<p style='font-size:12px;color:#a0aec0;margin-bottom:10px;'>Punteggio tecnico: <strong>" + techTotal + "/" + techMax + "</strong></p>";

            // raggruppa per prefisso area
            var webItems = [], emailItems = [], otherItems = [];
            var webKeys   = ["SSL", "Header", "CMS", "WAF", "HTTP", "File", "TLS", "Subdomain"];
            var emailKeys = ["MX", "DMARC", "SPF", "DKIM", "MTA", "DNSSEC"];
            for (var i = 0; i < s.details.length; i++) {
                var dd = s.details[i];
                var isWeb = webKeys.some(function(k){ return dd.area.toUpperCase().indexOf(k.toUpperCase()) >= 0; });
                var isEmail = emailKeys.some(function(k){ return dd.area.toUpperCase().indexOf(k.toUpperCase()) >= 0; });
                if (isWeb) webItems.push(dd);
                else if (isEmail) emailItems.push(dd);
                else otherItems.push(dd);
            }

            function renderGroup(label, items) {
                if (!items.length) return "";
                var out = "<tr><td colspan='3' style='background:rgba(43,108,176,0.15);font-weight:600;font-size:13px;padding:8px 10px;color:#63b3ed;'>" + label + "</td></tr>";
                for (var i = 0; i < items.length; i++) {
                    var dd = items[i];
                    var c = dd.score === dd.max ? "ok" : dd.score === 0 ? "error" : "warning";
                    var pct = dd.max > 0 ? Math.round((dd.score/dd.max)*100) : 0;
                    var bar = "<div style='width:60px;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;display:inline-block;vertical-align:middle;margin-left:6px;'><div style='width:" + pct + "%;height:100%;border-radius:3px;background:" + (c==="ok"?"#68d391":c==="warning"?"#f6e05e":"#fc8181") + ";'></div></div>";
                    out += "<tr><td style='font-size:13px;'>" + dd.area + "</td><td class='" + c + "' style='white-space:nowrap;'>" + dd.score + "/" + dd.max + bar + "</td><td style='font-size:12px;color:#a0aec0;'>" + dd.note + "</td></tr>";
                }
                return out;
            }

            h += "<table><tr><th>Controllo</th><th>Punteggio</th><th>Dettaglio</th></tr>";
            h += renderGroup("🌐 Sito web & infrastruttura", webItems);
            h += renderGroup("📧 Email & DNS", emailItems);
            if (otherItems.length) h += renderGroup("📋 Altro", otherItems);
            h += "</table></div>";

            // ---- QUESTIONARIO ----
            h += "<div class='card'><h3>Questionario di Autovalutazione</h3><table>";
            for (var k = 0; k < s.questionnaire_details.length; k++) {
                var q = s.questionnaire_details[k];
                var cls = q.answer === "si" ? "ok" : q.answer === "parziale" ? "warning" : "error";
                var label = q.answer === "si" ? "✅ Sì" : q.answer === "parziale" ? "⚠️ Parziale" : "❌ No";
                h += "<tr><td style='font-size:13px;'>" + q.question + "</td><td class='" + cls + "' style='white-space:nowrap;font-size:13px;'>" + label + "</td></tr>";
            }
            h += "</table></div>";

            // ---- AZIONI PRIORITARIE ----
            if (s.recommendations && s.recommendations.length > 0) {
                h += "<div class='card'><h3>⚠️ Azioni Prioritarie Tecniche</h3><ul style='padding-left:18px;'>";
                for (var m = 0; m < s.recommendations.length; m++) h += "<li style='margin-bottom:6px;font-size:13px;'>" + s.recommendations[m] + "</li>";
                h += "</ul></div>";
            }

            // ---- GAP ANALYSIS QUESTIONARIO ----
            if (s.questionnaire_gaps && s.questionnaire_gaps.length > 0) {
                var weightColors = { "CRITICO": "#fc8181", "ALTO": "#f6ad55", "MEDIO": "#f6e05e", "BASSO": "#63b3ed" };
                var weightBg    = { "CRITICO": "rgba(252,129,129,0.08)", "ALTO": "rgba(246,173,85,0.08)", "MEDIO": "rgba(246,224,94,0.08)", "BASSO": "rgba(99,179,237,0.08)" };
                var weightBorder= { "CRITICO": "rgba(252,129,129,0.3)", "ALTO": "rgba(246,173,85,0.3)", "MEDIO": "rgba(246,224,94,0.3)", "BASSO": "rgba(99,179,237,0.2)" };

                var critici = s.questionnaire_gaps.filter(function(g){ return g.weight === "CRITICO"; });
                var alti    = s.questionnaire_gaps.filter(function(g){ return g.weight === "ALTO"; });
                var medi    = s.questionnaire_gaps.filter(function(g){ return g.weight === "MEDIO"; });

                h += "<div class='card'>";
                h += "<h3>📋 Analisi Lacune Governance NIS2</h3>";
                h += "<p style='font-size:12px;color:#a0aec0;margin-bottom:16px;'>Peso delle lacune in base alla categoria NIS2 dell'organizzazione (<strong style='color:" + (s.nis2_category.category === 'Essenziale' ? '#fc8181' : '#f6e05e') + ";'>" + s.nis2_category.category + "</strong>).</p>";

                function renderGaps(gaps) {
                    var out = "";
                    for (var gi = 0; gi < gaps.length; gi++) {
                        var g = gaps[gi];
                        var bc = weightBg[g.weight] || "rgba(255,255,255,0.04)";
                        var br = weightBorder[g.weight] || "rgba(255,255,255,0.1)";
                        var wc = weightColors[g.weight] || "#a0aec0";
                        var answerLabel = g.answer === "parziale" ? "⚠️ Parziale" : "❌ Assente";
                        out += "<div style='background:" + bc + ";border:1px solid " + br + ";border-radius:8px;padding:12px 14px;margin-bottom:10px;'>";
                        out += "<div style='display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap;'>";
                        out += "<span style='background:" + wc + ";color:#0a1628;font-size:11px;font-weight:700;padding:3px 9px;border-radius:12px;'>" + g.weight + "</span>";
                        out += "<strong style='font-size:13px;color:#e2e8f0;'>" + g.label + "</strong>";
                        out += "<span style='font-size:11px;color:#718096;margin-left:auto;'>" + answerLabel + " &mdash; " + g.art + "</span>";
                        out += "</div>";
                        out += "<p style='font-size:12px;color:#a0aec0;margin:0 0 4px;'>🔴 <em>" + g.consequence + "</em></p>";
                        out += "<p style='font-size:12px;color:#68d391;margin:0;'>🛠️ Versione portable: " + g.portable + "</p>";
                        out += "</div>";
                    }
                    return out;
                }

                if (critici.length) { h += "<div style='font-size:12px;font-weight:700;color:#fc8181;margin:10px 0 6px;text-transform:uppercase;letter-spacing:.06em;'>Lacune critiche</div>"; h += renderGaps(critici); }
                if (alti.length)    { h += "<div style='font-size:12px;font-weight:700;color:#f6ad55;margin:10px 0 6px;text-transform:uppercase;letter-spacing:.06em;'>Lacune alte</div>";    h += renderGaps(alti); }
                if (medi.length)    { h += "<div style='font-size:12px;font-weight:700;color:#f6e05e;margin:10px 0 6px;text-transform:uppercase;letter-spacing:.06em;'>Lacune medie</div>";   h += renderGaps(medi); }
                h += "</div>";
            }

            // ---- CERTIFICAZIONI ----
            if (s.certifications && s.certifications.length > 0) {
                h += "<div class='card'><h3>Equivalenza Certificazioni</h3><table><tr><th>Certificazione</th><th>Readiness</th><th>Note</th></tr>";
                for (var c2 = 0; c2 < s.certifications.length; c2++) {
                    var cert = s.certifications[c2];
                    var cc = cert.readiness === "Alta" ? "ok" : cert.readiness === "Media" ? "warning" : "error";
                    h += "<tr><td>" + cert.certification + "</td><td class='" + cc + "'>" + cert.readiness + "</td><td style='font-size:12px;'>" + cert.note + "</td></tr>";
                }
                h += "</table></div>";
            }

            // ---- ALERT DINAMICO CTA ----
            var gaps = s.questionnaire_gaps || [];
            var critCount = gaps.filter(function(g){ return g.weight === "CRITICO"; }).length;
            var cat = s.nis2_category ? s.nis2_category.category : "Altro";
            var employees = d.company.employees || "";

            var alertBg, alertBorder, alertIcon, alertTitle, alertMsg;
            if (critCount >= 2 && cat === "Essenziale") {
                alertBg = "rgba(252,129,129,0.1)"; alertBorder = "rgba(252,129,129,0.5)";
                alertIcon = "🚨"; alertTitle = "ATTENZIONE — Organizzazione Essenziale con lacune critiche";
                alertMsg = "La tua organizzazione rientra nelle <strong>entità essenziali NIS2</strong> e presenta <strong>" + critCount + " lacune critiche</strong>. In caso di incidente o audit, le sanzioni possono raggiungere il <strong>2% del fatturato globale o 10 milioni di euro</strong>. È necessario un piano di adeguamento immediato.";
            } else if (critCount >= 1 || cat === "Essenziale") {
                alertBg = "rgba(246,173,85,0.1)"; alertBorder = "rgba(246,173,85,0.5)";
                alertIcon = "⚠️"; alertTitle = "Intervento prioritario richiesto";
                alertMsg = "Sono presenti lacune di governance che devono essere colmate prima della scadenza NIS2. La versione portable include strumenti specifici per i processi mancanti.";
            } else {
                alertBg = "rgba(99,179,237,0.08)"; alertBorder = "rgba(99,179,237,0.3)";
                alertIcon = "🔍"; alertTitle = "Analisi completa consigliata";
                alertMsg = "Il Quick Scan copre la superficie pubblica. Per una valutazione NIS2 completa — inclusa rete interna, endpoint e processi — utilizza la versione portable.";
            }

            var critLabels = gaps.filter(function(g){ return g.weight === "CRITICO"; }).map(function(g){ return g.label; });
            var gapListHtml = critLabels.length
                ? "<ul style='padding-left:18px;margin:10px 0;'>" + critLabels.map(function(l){ return "<li style='font-size:13px;color:#e2e8f0;margin-bottom:4px;'>❌ " + l + "</li>"; }).join("") + "</ul>"
                : "";

            h += "<div style='background:" + alertBg + ";border:2px solid " + alertBorder + ";border-radius:12px;padding:24px;margin-top:20px;'>";
            h += "<h3 style='color:#e2e8f0;margin-top:0;font-size:18px;'>" + alertIcon + " " + alertTitle + "</h3>";
            h += "<p style='font-size:14px;color:#cbd5e0;margin-bottom:10px;'>" + alertMsg + "</p>";
            h += gapListHtml;
            h += "<p style='font-size:13px;color:#68d391;font-weight:600;margin:14px 0 6px;'>La versione portable include, oltre agli 11 controlli automatici:</p>";
            h += "<ul style='padding-left:18px;margin:0 0 18px;'>";
            h += "<li style='font-size:13px;color:#cbd5e0;margin-bottom:4px;'>📋 Analisi dei rischi guidata con reportistica PDF NIS2</li>";
            h += "<li style='font-size:13px;color:#cbd5e0;margin-bottom:4px;'>🔔 Workflow notifica incidenti ad ACN (24h/72h)</li>";
            h += "<li style='font-size:13px;color:#cbd5e0;margin-bottom:4px;'>🔗 Questionario e scoring sicurezza fornitori</li>";
            h += "<li style='font-size:13px;color:#cbd5e0;margin-bottom:4px;'>👤 Modulo CISO virtuale con KPI e roadmap</li>";
            h += "<li style='font-size:13px;color:#cbd5e0;margin-bottom:4px;'>🖥️ Scan rete interna: porte, endpoint, BitLocker, firewall</li>";
            h += "</ul>";
            h += "<a href='#' class='btn-download' onclick=\"alert('Contattaci per la versione portable.'); return false;\">⬇️ RICHIEDI LA VERSIONE PORTABLE</a>";
            h += "<p style='font-size:11px;color:#718096;margin-top:10px;text-align:center;'>Licenza a pagamento • Include 30 giorni di aggiornamenti e supporto</p>";
            h += "</div>";
            
            // BOX DOWNLOAD PORTABLE
            h += "<div class='download-box'>";
            h += "<h3>🔍 Vuoi un'analisi completa della rete interna?</h3>";
            h += "<p>La versione cloud analizza solo la superficie pubblica. Con la <strong>versione portable</strong> puoi eseguire:</p>";
            h += "<ul class='features-list'>";
            h += "<li><span>🔐</span> Scan porte interne (RDP, SMB, FTP, Telnet)</li>";
            h += "<li><span>🛡️</span> Verifica firewall e antivirus aziendali</li>";
            h += "<li><span>💻</span> Controllo BitLocker e crittografia endpoint</li>";
            h += "<li><span>📡</span> Rilevamento automatico dominio e rete locale</li>";
            h += "<li><span>📊</span> Report NIS2 completo con punteggio esteso</li>";
            h += "</ul>";
            h += "<p style='color:#68d391; font-weight:600; margin:15px 0;'>Scarica la versione portable ed esegui lo scan completo dalla tua rete aziendale.</p>";
            h += "<a href='#' class='btn-download' onclick='alert(\"Versione portable in arrivo. Contattaci per maggiori informazioni.\"); return false;'>⬇️ SCARICA VERSIONE PORTABLE</a>";
            h += "<p style='font-size:11px;color:#718096;margin-top:10px;'>Licenza a pagamento • Include 30 giorni di aggiornamenti</p>";
            h += "</div>";
            
            document.getElementById("results").innerHTML = h;
            document.getElementById("results").scrollIntoView({ behavior: "smooth" });
        }
    </script>
</body>
</html>
"""

# ============================================================
# ROTTE API (solo web)
# ============================================================

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

def _clean_company_name(name):
    """Restituisce una stringa pulita da usare come base per il dominio."""
    import unicodedata
    import re
    # Normalizza accenti (es. "Società" -> "Societa")
    name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')
    name = name.lower()
    # Rimuove suffissi legali comuni (ordine: dal più lungo al più corto)
    suffixes = ['societa per azioni', 'societa a responsabilita limitata semplificata',
                'societa a responsabilita limitata', 'societa in accomandita semplice',
                'societa in nome collettivo', 'srls', 'srl', 'spa', 'snc', 'sas',
                'sapa', 'scrl', 'scarl', 'onlus', 'aps', 'ets', 'asd', 'soc coop',
                'cooperativa', 'coop', 'group', 'gruppo', 'holding', 'italia', 'italian']
    for s in suffixes:
        name = re.sub(r'\b' + re.escape(s) + r'\b', '', name)
    # Rimuove caratteri non alfanumerici (tranne spazi e trattini)
    name = re.sub(r'[^a-z0-9 \-]', '', name)
    # Compatta spazi e trattini multipli
    name = re.sub(r'[\s\-]+', '-', name).strip('-')
    return name


def _domain_resolves(domain):
    """Verifica che il dominio risponda ad una query DNS A o CNAME."""
    for record_type in ('A', 'CNAME'):
        try:
            dns.resolver.resolve(domain, record_type, lifetime=1)
            return True
        except Exception:
            pass
    return False


def find_company_domain(company_name):
    """
    Cerca il dominio aziendale provando solo le varianti più probabili
    con timeout ridotto. Max 6 tentativi DNS (< 6 secondi totali).
    """
    base = _clean_company_name(company_name)
    if not base:
        return None

    first_word = base.split('-')[0]

    # Candidati prioritari: solo .it e .com
    candidates = []
    for b in ([base] + ([first_word] if first_word != base and len(first_word) > 2 else [])):
        candidates.append(b + '.it')
        candidates.append(b + '.com')

    for candidate in candidates[:6]:  # max 6 query DNS
        if _domain_resolves(candidate):
            return candidate

    # Fallback immediato
    return base + '.it'


@app.route('/api/test-lookup', methods=['POST'])
def test_lookup():
    vat = request.json.get('vat_number', '')
    if not vat or len(vat) < 11:
        return jsonify({"success": False})
    company_data = lookup_company(vat)
    if company_data and company_data.get('name') and company_data['name'] != 'Partita IVA non trovata':
        domain_hint = find_company_domain(company_data['name'])

        # ATECO: scarta valori non informativi
        _INVALID_ATECO = {'', 'n/d', 'nd', 'n.d.', 'non disponibile', 'null', 'none', '-'}
        ateco_raw = str(company_data.get('ateco', '') or '').strip()
        if ateco_raw.lower() in _INVALID_ATECO:
            ateco_raw = ''

        # Dipendenti: normalizza a intero, scarta se non significativo
        employees_raw = (
            company_data.get('employees', '')
            or company_data.get('addetti', '')
            or company_data.get('numero_addetti', '')
            or ''
        )
        employees_count = None
        if str(employees_raw).strip().lower() not in _INVALID_ATECO:
            try:
                n = int(''.join(filter(str.isdigit, str(employees_raw))))
                employees_count = n if n > 0 else None
            except (ValueError, TypeError):
                pass

        return jsonify({
            "success": True,
            "name": company_data['name'],
            "address": company_data.get('address', ''),
            "domain_hint": domain_hint,
            "ateco": ateco_raw,          # stringa vuota = non disponibile
            "employees_count": employees_count   # None = non disponibile
        })
    return jsonify({"success": False})

@app.route('/api/verify-dns', methods=['POST'])
def verify_dns():
    email = request.json.get('email', '')
    domain = email.split('@')[-1] if '@' in email else ''
    results = {
        "email": email, "domain": domain,
        "mx_valid": False, "mx_count": 0,
        "spf_valid": False, "spf_strict": False, "spf_record": "",
        "dmarc_valid": False, "dmarc_policy": "", "dmarc_rua": False,
        "dkim_verified": False, "dkim_selector": "",
        "mta_sts": False,
        "score": 0
    }

    # MX
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
        results["mx_valid"] = True
        results["mx_count"] = len(list(mx_answers))
        results["score"] += 5
    except Exception:
        pass

    # SPF
    try:
        for rdata in dns.resolver.resolve(domain, 'TXT', lifetime=3):
            t = str(rdata)
            if "v=spf1" in t:
                results["spf_valid"] = True
                results["spf_record"] = t[:120]
                results["spf_strict"] = "-all" in t
                results["score"] += 5 if results["spf_strict"] else 3
                break
    except Exception:
        pass

    # DMARC
    try:
        for rdata in dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=3):
            t = str(rdata)
            if "v=DMARC1" in t:
                results["dmarc_valid"] = True
                results["dmarc_rua"] = "rua=" in t
                if "p=reject" in t:
                    results["dmarc_policy"] = "reject"
                    results["score"] += 8
                elif "p=quarantine" in t:
                    results["dmarc_policy"] = "quarantine"
                    results["score"] += 5
                else:
                    results["dmarc_policy"] = "none"
                    results["score"] += 2
                break
    except Exception:
        pass

    # DKIM — prova i selettori più comuni
    dkim_selectors = [
        "default", "google", "mail", "smtp", "dkim",
        "selector1", "selector2",   # Microsoft 365
        "k1", "k2",                  # Mailchimp/Mandrill
        "s1", "s2",
        "email",                     # SendGrid
        "mx",                        # Zoho
        "protonmail",
        "amazonses",
    ]
    for sel in dkim_selectors:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", 'TXT', lifetime=2)
            results["dkim_verified"] = True
            results["dkim_selector"] = sel
            results["score"] += 7
            break
        except Exception:
            continue

    # MTA-STS (RFC 8461) — protegge il canale SMTP in ingresso
    try:
        for rdata in dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT', lifetime=3):
            if "v=STSv1" in str(rdata):
                results["mta_sts"] = True
                results["score"] += 5
                break
    except Exception:
        pass

    results["level"] = (
        "CONFORME"     if results["score"] >= 25 else
        "PARZIALE"     if results["score"] >= 12 else
        "NON CONFORME"
    )
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
    company_data["is_corporate_network"] = False  # Forzato a False nella versione web
    domain = data.get('domain', '')
    scan_results = scan_domain(domain)
    score = calculate_nis2_score(company_data, scan_results, questions)
    return jsonify({"company": company_data, "domain": domain, "score": score})

if __name__ == '__main__':
    app.run(debug=True)