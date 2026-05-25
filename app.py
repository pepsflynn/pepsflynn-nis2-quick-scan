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
            <p style="font-size:12px;color:#a0aec0;">Questa versione web esegue scan del dominio pubblico e DNS. Per l'analisi completa della rete interna, scarica la versione portable.</p>
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
            <p style="color:#a0aec0; margin-bottom:15px; font-size:13px;">☁️ Scan della superficie pubblica. Rete locale ed endpoint richiedono la <strong>versione portable</strong>.</p>
            
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
            
            <div style="background:rgba(43,108,176,0.1);border:1px solid rgba(43,108,176,0.3);border-radius:8px;padding:12px;margin-top:15px;">
                <p style="font-size:13px;color:#63b3ed;"><strong>🔍 Scan di rete ed endpoint non disponibili nella versione cloud</strong></p>
                <p style="font-size:12px;color:#a0aec0;">RDP, SMB, porte, firewall, antivirus, BitLocker e altri controlli interni sono disponibili solo nella <strong>versione portable</strong> da eseguire sulla rete aziendale.</p>
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
                                    var atecoOk = d.ateco ? autoSelectAteco(d.ateco) : false;
                                    var empOk = (d.employees_count !== null && d.employees_count !== undefined) ? autoSelectEmployees(d.employees_count) : false;
                                    showFieldHint('ateco-hint', atecoOk,
                                        '✅ Settore ATECO rilevato automaticamente: <strong>' + d.ateco + '</strong>',
                                        '⚠️ Settore ATECO non disponibile nei registri pubblici — selezionalo manualmente.');
                                    showFieldHint('employees-hint', empOk,
                                        '✅ Numero dipendenti rilevato automaticamente.',
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

        function autoSelectAteco(code) {
            if (!code) return false;
            var map = [
                { prefix: '35', value: '35' },
                { prefix: '49', value: '49' }, { prefix: '50', value: '49' },
                { prefix: '51', value: '49' }, { prefix: '52', value: '49' }, { prefix: '53', value: '49' },
                { prefix: '86', value: '86' }, { prefix: '87', value: '86' }, { prefix: '88', value: '86' },
                { prefix: '61', value: '61' },
                { prefix: '62', value: '62' },
                { prefix: '63', value: '63' },
                { prefix: '64', value: '64' }, { prefix: '65', value: '64' }, { prefix: '66', value: '64' },
                { prefix: '84', value: '84' }
            ];
            var clean = code.replace(/\./g, '');
            var sel = document.getElementById('ateco');
            if (sel.value) return true; // già compilato, considera ok
            for (var i = 0; i < map.length; i++) {
                if (clean.startsWith(map[i].prefix)) {
                    sel.value = map[i].value;
                    sel.style.borderColor = '#68d391';
                    setTimeout(function() { sel.style.borderColor = ''; }, 2000);
                    return true;
                }
            }
            sel.value = 'altro';
            sel.style.borderColor = '#68d391';
            setTimeout(function() { sel.style.borderColor = ''; }, 2000);
            return true;
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

        function verifyDNS() {
            var email = document.getElementById("email").value.trim();
            if (!email) { alert("Inserisci un indirizzo email"); return; }
            var btn = document.getElementById("btn-dns");
            btn.disabled = true; btn.textContent = "Analisi...";
            fetch("/api/verify-dns", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: email}) })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success) {
                    var r = d.results, h = "<table style='margin-top:10px;'>";
                    h += "<tr><td>MX</td><td class='"+(r.mx_valid?"ok":"error")+"'>"+(r.mx_valid?"OK":"NO")+"</td></tr>";
                    h += "<tr><td>SPF</td><td class='"+(r.spf_valid?"ok":"error")+"'>"+(r.spf_valid?"OK":"NO")+"</td></tr>";
                    h += "<tr><td>DMARC</td><td class='"+(r.dmarc_valid?"ok":"error")+"'>"+(r.dmarc_valid?"OK "+r.dmarc_policy:"NO")+"</td></tr>";
                    h += "<tr><td>DKIM</td><td class='"+(r.dkim_verified?"ok":"error")+"'>"+(r.dkim_verified?"OK":"NO")+"</td></tr>";
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
            var h = "<div class='card' style='text-align:center;'><h2>Report Quick Scan NIS2</h2>";
            h += "<div class='score-circle score-" + rc + "'>" + s.total_score + "/100</div>";
            h += "<p class='" + s.risk_color + "'>Rischio: " + s.overall_risk + "</p>";
            h += "<p style='font-size:12px;color:#a0aec0;'>☁️ Versione Cloud - Solo superficie pubblica</p></div>";
            
            h += "<div class='card'><h3>Dati</h3><table>";
            h += "<tr><td>Azienda</td><td>" + d.company.name + "</td></tr>";
            h += "<tr><td>Settore</td><td>" + d.company.ateco + "</td></tr>";
            h += "<tr><td>Dipendenti</td><td>" + d.company.employees + "</td></tr>";
            h += "<tr><td>CISO</td><td>" + (d.company.ciso || "N/D") + "</td></tr></table></div>";
            
            h += "<div class='card'><h3>Scan Tecnici</h3><table><tr><th>Test</th><th>Punteggio</th><th>Note</th></tr>";
            for (var i = 0; i < s.details.length; i++) { var dd = s.details[i], c = dd.score === dd.max ? "ok" : dd.score === 0 ? "error" : "warning"; h += "<tr><td>" + dd.area + "</td><td class='" + c + "'>" + dd.score + "/" + dd.max + "</td><td>" + dd.note + "</td></tr>"; }
            h += "</table></div>";
            
            h += "<div class='card'><h3>Questionario</h3><table>";
            for (var k = 0; k < s.questionnaire_details.length; k++) { var q = s.questionnaire_details[k]; h += "<tr><td>" + q.question + "</td><td class='" + (q.answer === "si" ? "ok" : "error") + "'>" + (q.answer === "si" ? "Si" : "No") + "</td></tr>"; }
            h += "</table></div>";
            
            if (s.recommendations.length > 0) { h += "<div class='card'><h3>Azioni Prioritarie</h3><ul>"; for (var m = 0; m < s.recommendations.length; m++) h += "<li>" + s.recommendations[m] + "</li>"; h += "</ul></div>"; }
            
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
            dns.resolver.resolve(domain, record_type, lifetime=3)
            return True
        except Exception:
            pass
    return False


def find_company_domain(company_name):
    """
    Prova sistematicamente varianti del dominio aziendale e restituisce
    il primo che risponde al DNS, oppure la variante .it come fallback.
    """
    base = _clean_company_name(company_name)
    if not base:
        return None

    # Genera candidati: nome intero, poi senza trattini, poi prima parola
    bases = [base]
    no_dash = base.replace('-', '')
    if no_dash != base:
        bases.append(no_dash)
    first_word = base.split('-')[0]
    if first_word not in bases and len(first_word) > 2:
        bases.append(first_word)

    tlds = ['.it', '.com', '.eu', '.net', '.org']

    for b in bases:
        for tld in tlds:
            candidate = b + tld
            if _domain_resolves(candidate):
                return candidate

    # Nessun dominio verificato → restituisce il fallback più probabile
    return bases[0] + '.it'


@app.route('/api/test-lookup', methods=['POST'])
def test_lookup():
    vat = request.json.get('vat_number', '')
    if not vat or len(vat) < 11:
        return jsonify({"success": False})
    company_data = lookup_company(vat)
    if company_data and company_data.get('name') and company_data['name'] != 'Partita IVA non trovata':
        domain_hint = find_company_domain(company_data['name'])
        ateco_raw = company_data.get('ateco', '') or ''
        employees_raw = company_data.get('employees', '') or company_data.get('addetti', '') or ''
        employees_count = None
        try:
            employees_count = int(''.join(filter(str.isdigit, str(employees_raw)))) if employees_raw else None
        except (ValueError, TypeError):
            pass
        return jsonify({
            "success": True,
            "name": company_data['name'],
            "address": company_data.get('address', ''),
            "domain_hint": domain_hint,
            "ateco": ateco_raw,
            "employees_count": employees_count
        })
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