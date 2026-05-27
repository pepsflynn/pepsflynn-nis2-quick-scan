from flask import Flask, render_template_string, request, jsonify
from company_lookup import lookup_company
from domain_scanner import scan_domain
from scoring import calculate_nis2_score
import random
import string
import dns.resolver
import os
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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
            <label>Settore (codice ATECO principale)
                <a href="https://www.ufficiocamerale.it/trova-azienda" target="_blank"
                   style="font-size:11px;color:#63b3ed;margin-left:8px;font-weight:400;">
                   🔍 Cerca ATECO →</a>
            </label>
            <select id="ateco" onchange="computeNIS2Category()">
                <option value="">— Seleziona il settore principale —</option>
                <optgroup label="Allegato I — Settori Essenziali">
                    <option value="35">Energia elettrica, gas, vapore (35.x)</option>
                    <option value="06">Estrazione petrolio e gas naturale (06.x)</option>
                    <option value="19">Raffinerie e prodotti petroliferi (19.x)</option>
                    <option value="49">Trasporti terrestri e oleodotti (49.x)</option>
                    <option value="50">Trasporti marittimi e per vie d'acqua (50.x)</option>
                    <option value="51">Trasporti aerei (51.x)</option>
                    <option value="52">Magazzinaggio e supporto ai trasporti (52.x)</option>
                    <option value="36">Raccolta e trattamento acqua potabile (36.x)</option>
                    <option value="37">Gestione acque reflue (37.x)</option>
                    <option value="61">Telecomunicazioni (61.x)</option>
                    <option value="62">Produzione software e servizi IT (62.x)</option>
                    <option value="63">Elaborazione dati e data center (63.x)</option>
                    <option value="64">Banche e intermediazione creditizia (64.x)</option>
                    <option value="65">Assicurazioni e fondi pensione (65.x)</option>
                    <option value="66">Attività ausiliarie dei servizi finanziari (66.x)</option>
                    <option value="84">Pubblica Amministrazione (84.x)</option>
                    <option value="86">Assistenza ospedaliera e sanitaria (86.x)</option>
                    <option value="87">Assistenza residenziale (87.x)</option>
                    <option value="88">Assistenza sociale non residenziale (88.x)</option>
                </optgroup>
                <optgroup label="Allegato II — Settori Importanti">
                    <option value="53">Servizi postali e corrieri (53.x)</option>
                    <option value="38">Raccolta e smaltimento rifiuti (38.x)</option>
                    <option value="20">Fabbricazione prodotti chimici (20.x)</option>
                    <option value="21">Fabbricazione prodotti farmaceutici (21.x)</option>
                    <option value="22">Fabbricazione materie plastiche e gomma (22.x)</option>
                    <option value="10">Industria alimentare (10.x)</option>
                    <option value="11">Industria delle bevande (11.x)</option>
                    <option value="24">Metallurgia (24.x)</option>
                    <option value="25">Fabbricazione prodotti in metallo (25.x)</option>
                    <option value="26">Fabbricazione apparecchi elettronici (26.x)</option>
                    <option value="27">Fabbricazione apparecchiature elettriche (27.x)</option>
                    <option value="28">Fabbricazione macchinari industriali (28.x)</option>
                    <option value="29">Fabbricazione autoveicoli (29.x)</option>
                    <option value="30">Fabbricazione altri mezzi di trasporto (30.x)</option>
                    <option value="72">Ricerca e sviluppo scientifico (72.x)</option>
                    <option value="73">Ricerca e sviluppo in ingegneria (73.x)</option>
                    <option value="58">Editoria e media (58-60.x)</option>
                </optgroup>
                <optgroup label="Fuori ambito NIS2">
                    <option value="altro">Altro settore (commercio, turismo, ristorazione…)</option>
                </optgroup>
            </select>
            <div id="ateco-hint" style="display:none; font-size:12px; margin-top:-6px; margin-bottom:10px; padding:8px 10px; border-radius:6px;"></div>

            <label>Numero dipendenti</label>
            <select id="employees" onchange="computeNIS2Category()">
                <option value="">Seleziona...</option>
                <option value="1-10">1 – 10 (micro impresa)</option>
                <option value="11-50">11 – 50 (piccola impresa)</option>
                <option value="51-250">51 – 250 (media impresa)</option>
                <option value="250+">Oltre 250 (grande impresa)</option>
            </select>
            <div id="employees-hint" style="display:none; font-size:12px; margin-top:-6px; margin-bottom:10px; padding:8px 10px; border-radius:6px;"></div>

            <label>Fascia fatturato annuo</label>
            <select id="revenue" onchange="computeNIS2Category()">
                <option value="">Seleziona...</option>
                <option value="micro">Fino a 2 M€ (micro impresa)</option>
                <option value="piccola">2 – 10 M€ (piccola impresa)</option>
                <option value="media">10 – 50 M€ (media impresa)</option>
                <option value="grande">Oltre 50 M€ (grande impresa)</option>
            </select>

            <label style="margin-top:6px;display:block;">Fornisci servizi a organizzazioni nei settori energia, sanità, PA, finanza, TLC o infrastrutture critiche?</label>
            <p style="font-size:12px;color:#718096;margin:-4px 0 8px;">Es: sei un fornitore IT, consulente, system integrator o outsourcer di un ente pubblico, ospedale, banca o utility?</p>
            <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;">
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:8px 14px;font-size:13px;color:#cbd5e0;">
                    <input type="radio" name="is_supplier" value="si" onchange="computeNIS2Category()" style="accent-color:#63b3ed;"> Sì, sono fornitore di soggetti NIS2</label>
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:8px 14px;font-size:13px;color:#cbd5e0;">
                    <input type="radio" name="is_supplier" value="forse" onchange="computeNIS2Category()" style="accent-color:#63b3ed;"> Potrei esserlo, non sono sicuro</label>
                <label style="display:flex;align-items:center;gap=6px;cursor:pointer;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:8px 14px;font-size:13px;color:#cbd5e0;">
                    <input type="radio" name="is_supplier" value="no" onchange="computeNIS2Category()" style="accent-color:#63b3ed;"> No</label>
            </div>
            <div id="nis2-badge" style="display:none; border-radius:8px; padding:12px 14px; margin:10px 0 14px;"></div>
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
                <p style="font-size:12px;color:#a0aec0;margin-bottom:10px;">
                    Inviamo un codice a 6 cifre all'email inserita sopra per verificare che esista e che tu ne abbia accesso.
                    Scade in 10 minuti.<span id="otp-countdown" style="display:none;font-size:12px;color:#f6ad55;"></span>
                </p>
                <button class="btn-small btn-outline" onclick="sendOTP()" id="btn-otp">📧 Invia codice OTP</button>
                <div id="otp-status" style="display:none;font-size:12px;padding:8px 12px;border-radius:6px;margin-top:8px;"></div>
                <div id="otp-verify-section" style="display:none;margin-top:12px;">
                    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                        <input type="text" id="otp-code" placeholder="Inserisci il codice a 6 cifre"
                               style="flex:1;min-width:160px;letter-spacing:6px;font-size:18px;text-align:center;"
                               maxlength="6" oninput="this.value=this.value.replace(/[^0-9]/g,'')">
                        <button class="btn-small" onclick="verifyOTP()" id="btn-verify-otp">✅ Verifica</button>
                    </div>
                    <div id="otp-verify-status" style="display:none;font-size:12px;padding:8px 12px;border-radius:6px;margin-top:8px;"></div>
                    <p style="font-size:11px;color:#718096;margin-top:8px;">
                        Non hai ricevuto l'email? Controlla lo spam oppure
                        <a href="#" onclick="sendOTP();return false;" style="color:#63b3ed;">invia di nuovo</a>.
                    </p>
                </div>
            </div>
            
            <div style="background:rgba(43,108,176,0.1);border:1px solid rgba(43,108,176,0.3);border-radius:8px;padding:12px;margin-top:15px;">
                <p style="font-size:13px;color:#63b3ed;"><strong>🏢 Rete interna — solo versione portable</strong></p>
                <p style="font-size:12px;color:#a0aec0;">RDP, SMB, firewall, antivirus, BitLocker, porte interne e crittografia endpoint richiedono la <strong>versione portable</strong> da eseguire sulla rete aziendale.</p>
            </div>

            <button onclick="goToStep3()" id="goto-step3" disabled class="btn-full" style="margin-top:15px;">Prosegui con il Questionario</button>
        </div>

        <!-- STEP 3: QUESTIONARIO -->
        <div class="card hidden" id="step3">
            <h3>📋 Questionario NIS2</h3>
            <p id="q-intro" style="color:#a0aec0; margin-bottom:5px; font-size:13px;"></p>
            <div id="q-category-badge" style="display:none; border-radius:6px; padding:8px 12px; margin-bottom:14px; font-size:13px;"></div>
            <div id="questionnaire-container"></div>
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

        // autoSelectAteco: fills select from lookup result, then recomputes NIS2 category
        function autoSelectAteco(code) {
            if (!code) return false;
            var clean = code.replace(/\./g,'');
            var sel = document.getElementById('ateco');
            if (sel.value) return { found: true, code: code, label: sel.options[sel.selectedIndex].text };
            // Find best matching option in the new grouped select
            var best = null;
            for (var i = 0; i < sel.options.length; i++) {
                var optVal = sel.options[i].value.replace(/\./g,'');
                if (optVal && clean.startsWith(optVal)) {
                    if (!best || optVal.length > best.len) best = { idx: i, len: optVal.length, label: sel.options[i].text };
                }
            }
            if (best) {
                sel.selectedIndex = best.idx;
                sel.style.borderColor = '#68d391';
                setTimeout(function(){ sel.style.borderColor = ''; }, 2000);
                computeNIS2Category();
                return { found: true, code: code, label: best.label };
            }
            return { found: false, code: code, label: '' };
        }
        function autoSelectEmployees(count) {
            if (count === null || count === undefined) return false;
            var n = parseInt(count);
            if (isNaN(n)) return false;
            var sel = document.getElementById('employees');
            if (sel.value) return true;
            if (n <= 10)       sel.value = '1-10';
            else if (n <= 50)  sel.value = '11-50';
            else if (n <= 250) sel.value = '51-250';
            else               sel.value = '250+';
            sel.style.borderColor = '#68d391';
            setTimeout(function() { sel.style.borderColor = ''; }, 2000);
            computeNIS2Category();
            return true;
        }

        // ── NIS2 category helpers ─────────────────────────────────────
        var ANNEX_I  = ['05','06','07','08','09','19','35','36','37','49','50','51','52','61','62','63','64','65','66','84','86','87','88'];
        var ANNEX_II = ['10','11','13','14','20','21','22','24','25','26','27','28','29','30','38','39','53','58','59','60','72','73'];

        function isAnnexI(code)  { var c = code.replace(/\./g,''); return ANNEX_I.some(function(p){ return c.startsWith(p); }); }
        function isAnnexII(code) { var c = code.replace(/\./g,''); return ANNEX_II.some(function(p){ return c.startsWith(p); }); }

        function computeNIS2Category() {
            var ateco    = document.getElementById('ateco').value;
            var emp      = document.getElementById('employees').value;
            var rev      = document.getElementById('revenue') ? document.getElementById('revenue').value : '';
            var badge    = document.getElementById('nis2-badge');
            if (!badge) return;
            if (!ateco || !emp) { badge.style.display='none'; window._nis2Category=''; return; }

            var isLarge  = emp === '250+' || rev === 'grande';
            var isMedium = (emp === '51-250' || rev === 'media') && !isLarge;
            var cat, desc, bg, border, color;

            if (ateco === '84') {
                cat='Essenziale'; desc='Pubblica Amministrazione — sempre Essenziale per legge';
            } else if (isAnnexI(ateco)) {
                if (isLarge)       { cat='Essenziale'; desc='Grande organizzazione in settore Allegato I NIS2'; }
                else if (isMedium) { cat='Importante'; desc='Media organizzazione in settore Allegato I NIS2'; }
                else               { cat='Fuori ambito'; desc='Piccola/micro impresa — NIS2 non obbligatorio (salvo eccezioni)'; }
            } else if (isAnnexII(ateco)) {
                if (isLarge || isMedium) { cat='Importante'; desc='Organizzazione in settore Allegato II NIS2'; }
                else                     { cat='Fuori ambito'; desc='Piccola/micro impresa — NIS2 non applicabile'; }
            } else {
                cat='Fuori ambito'; desc='Settore non coperto dalla Direttiva NIS2';
            }

            var styles = {
                'Essenziale':     { bg:'rgba(252,129,129,0.12)', border:'rgba(252,129,129,0.5)', color:'#fc8181', icon:'🔴' },
                'Importante':     { bg:'rgba(246,224,94,0.10)',  border:'rgba(246,224,94,0.5)',  color:'#f6e05e', icon:'🟡' },
                'Fuori ambito':   { bg:'rgba(99,179,237,0.08)',  border:'rgba(99,179,237,0.35)', color:'#63b3ed', icon:'⬜' },
                'Non determinabile': { bg:'rgba(160,174,192,0.1)', border:'rgba(160,174,192,0.3)', color:'#a0aec0', icon:'❓' }
            };
            var st = styles[cat] || styles['Non determinabile'];
            badge.style.display='block';
            badge.style.background=st.bg; badge.style.border='1px solid '+st.border;
            badge.innerHTML = st.icon+' Categoria NIS2 rilevata: <strong style="color:'+st.color+';">'+cat+'</strong> &mdash; <span style="color:#a0aec0;font-size:12px;">'+desc+'</span>';
            // Check supplier override
            var supplierEl = document.querySelector('input[name="is_supplier"]:checked');
            var supplierVal = supplierEl ? supplierEl.value : 'no';
            window._isSupplier = (supplierVal === 'si' || supplierVal === 'forse');

            if (window._isSupplier && cat === 'Fuori ambito') {
                cat = 'Fornitore NIS2';
                var supplierNote = supplierVal === 'forse'
                    ? 'Possibile fornitore di soggetti NIS2 — verifica se i tuoi clienti rientrano nell\'ambito'
                    : 'Fornitore di soggetti NIS2 — obblighi contrattuali derivati dall\'Art. 21.2.d';
                st = { bg:'rgba(156,135,226,0.10)', border:'rgba(156,135,226,0.45)', color:'#b794f4', icon:'🔗' };
                badge.style.display='block';
                badge.style.background=st.bg; badge.style.border='1px solid '+st.border;
                badge.innerHTML = st.icon+' Categoria NIS2 rilevata: <strong style="color:'+st.color+';">'+cat+'</strong> &mdash; <span style="color:#a0aec0;font-size:12px;">'+supplierNote+'</span>';
                badge.innerHTML += '<br><span style="color:#9f7aea;font-size:11px;display:block;margin-top:5px;">📋 Il questionario sarà calibrato sui requisiti che i tuoi clienti NIS2 ti chiederanno di rispettare</span>';
            }

            window._nis2Category = cat;
            if (!rev && cat !== 'Fornitore NIS2') badge.innerHTML += '<br><span style="color:#718096;font-size:11px;margin-top:4px;display:block;">⚠️ Aggiungere la fascia fatturato per una classificazione più precisa</span>';
        }

        // ── Questionnaire catalog ─────────────────────────────────
        var Q_CATALOG = {
            "Essenziale": [
                { id:"q1",  label:"Registrazione ACN + Punto di Contatto formale designato",         art:"Art. 7 D.Lgs. 138/2024",  badge:"OBBLIGO LEGALE", bc:"#fc8181",
                  opts:[{v:"si",l:"✅ Sì, completato e documentato"},{v:"in_corso",l:"⚠️ In corso / parziale"},{v:"no",l:"❌ No"}] },
                { id:"q2",  label:"CISO designato formalmente con mandato scritto e budget dedicato", art:"Art. 20 D.Lgs. 138/2024", badge:"OBBLIGO LEGALE", bc:"#fc8181",
                  opts:[{v:"si_interno",l:"✅ Sì, interno"},{v:"si_esterno",l:"✅ Sì, consulente esterno"},{v:"parziale",l:"⚠️ Identificato ma senza mandato formale"},{v:"no",l:"❌ No"}] },
                { id:"q3",  label:"Analisi dei rischi documentata e aggiornata almeno annualmente",  art:"Art. 21.2.a",             badge:"OBBLIGO LEGALE", bc:"#fc8181",
                  opts:[{v:"si",l:"✅ Sì, documentata e aggiornata"},{v:"parziale",l:"⚠️ Presente ma non aggiornata"},{v:"no",l:"❌ No"}] },
                { id:"q4",  label:"Piano notifica incidenti ad ACN 24h (primo report) + 72h (dettaglio)", art:"Art. 24 D.Lgs. 138/2024", badge:"OBBLIGO LEGALE", bc:"#fc8181",
                  opts:[{v:"si",l:"✅ Sì, piano testato"},{v:"parziale",l:"⚠️ Processo definito ma non testato"},{v:"no",l:"❌ No"}] },
                { id:"q5",  label:"Business Continuity Plan (BCP) formale e testato con esercitazioni", art:"Art. 21.2.c",           badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, BCP formale testato"},{v:"parziale",l:"⚠️ BCP redatto ma non testato"},{v:"no",l:"❌ No"}] },
                { id:"q6",  label:"MFA obbligatorio, cifratura endpoint, password policy formale",   art:"Art. 21.2.h, i",          badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, tutto implementato"},{v:"parziale",l:"⚠️ Parzialmente implementato"},{v:"no",l:"❌ No"}] },
                { id:"q7",  label:"Patch management strutturato con SLA definiti e registro vulnerabilità", art:"Art. 21.2.e",      badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, processo strutturato"},{v:"parziale",l:"⚠️ Gestito ma non formalizzato"},{v:"no",l:"❌ No"}] },
                { id:"q8",  label:"Audit sicurezza fornitori critici + contratti con clausole security", art:"Art. 21.2.d",         badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, audit e contratti aggiornati"},{v:"parziale",l:"⚠️ Solo verifica informale"},{v:"no",l:"❌ No"}] },
                { id:"q9",  label:"Formazione cybersicurezza obbligatoria, documentata e verificata", art:"Art. 20 D.Lgs. 138/2024", badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, programma strutturato"},{v:"saltuaria",l:"⚠️ Occasionale"},{v:"no",l:"❌ No"}] },
                { id:"q10", label:"Penetration test o audit di sicurezza indipendente (almeno annuale)", art:"Linee Guida ACN",     badge:"RACCOMANDATO", bc:"#f6e05e",
                  opts:[{v:"si",l:"✅ Sì, regolare"},{v:"parziale",l:"⚠️ Eseguito almeno una volta"},{v:"no",l:"❌ No"}] },
            ],
            "Importante": [
                { id:"q1", label:"Registrazione al portale ACN e designazione Punto di Contatto",    art:"Art. 7 D.Lgs. 138/2024",  badge:"OBBLIGO LEGALE", bc:"#fc8181",
                  opts:[{v:"si",l:"✅ Sì, completato"},{v:"in_corso",l:"⚠️ In corso"},{v:"no",l:"❌ No"}] },
                { id:"q2", label:"Responsabile della sicurezza informatica identificato",            art:"Art. 20 D.Lgs. 138/2024",  badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si_interno",l:"✅ Sì, interno"},{v:"si_esterno",l:"✅ Sì, esterno"},{v:"parziale",l:"⚠️ Identificato informalmente"},{v:"no",l:"❌ No"}] },
                { id:"q3", label:"Analisi dei rischi (anche semplificata) documentata",              art:"Art. 21.2.a",               badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, documentata"},{v:"parziale",l:"⚠️ Informale / non aggiornata"},{v:"no",l:"❌ No"}] },
                { id:"q4", label:"Processo gestione incidenti con notifica ad ACN entro 72h",       art:"Art. 24 D.Lgs. 138/2024",  badge:"OBBLIGO LEGALE", bc:"#fc8181",
                  opts:[{v:"si",l:"✅ Sì, processo definito"},{v:"parziale",l:"⚠️ Gestito caso per caso"},{v:"no",l:"❌ No"}] },
                { id:"q5", label:"MFA attivo, backup verificati e cifratura dati critici",          art:"Art. 21.2.h, i",            badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, implementato"},{v:"parziale",l:"⚠️ Parzialmente"},{v:"no",l:"❌ No"}] },
                { id:"q6", label:"Verifica sicurezza fornitori e partner critici",                  art:"Art. 21.2.d",               badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, verificati"},{v:"parziale",l:"⚠️ Solo i più critici"},{v:"no",l:"❌ No"}] },
                { id:"q7", label:"Formazione cybersicurezza per dipendenti e collaboratori",        art:"Art. 20 D.Lgs. 138/2024",  badge:"OBBLIGATORIO", bc:"#f6ad55",
                  opts:[{v:"si",l:"✅ Sì, programma attivo"},{v:"saltuaria",l:"⚠️ Occasionale"},{v:"no",l:"❌ No"}] },
            ],
            "Fornitore NIS2": [
                { id:"fq1", label:"Accessi remoti ai sistemi del cliente: nominativi, MFA obbligatoria, session recording", art:"Art. 21.2.d — Supply Chain", badge:"REQUISITO CRITICO", bc:"#fc8181",
                  note:"Il cliente NIS2 verificherà questo come primo requisito contrattuale",
                  opts:[{v:"si",l:"✅ Sì, MFA + accessi nominativi tracciati con log"},{v:"parziale",l:"⚠️ MFA presente ma accessi non tracciati/nominativi"},{v:"no",l:"❌ No"}] },
                { id:"fq2", label:"PAM: account privilegiati separati, accessi temporanei approvati e tracciati", art:"Art. 21.2.d — Supply Chain", badge:"REQUISITO CRITICO", bc:"#fc8181",
                  note:"Account condivisi o privilegiati non revocati = responsabilità diretta in caso di incidente",
                  opts:[{v:"si",l:"✅ Sì, PAM implementato con least privilege"},{v:"parziale",l:"⚠️ Separazione account ma senza PAM formalizzato"},{v:"no",l:"❌ No, account condivisi o non segregati"}] },
                { id:"fq3", label:"Incident Response Plan con notifica al cliente entro 24-48h dall'evento", art:"Art. 21.2.d + Art. 24", badge:"REQUISITO CRITICO", bc:"#fc8181",
                  note:"Il cliente NIS2 deve notificare ACN entro 24h — deve ricevere la tua segnalazione prima",
                  opts:[{v:"si",l:"✅ Sì, IRP con SLA di notifica definiti e testati"},{v:"parziale",l:"⚠️ Processo informale, nessun SLA formalizzato"},{v:"no",l:"❌ No IRP"}] },
                { id:"fq4", label:"BCP/DRP con RTO e RPO definiti e testati per i servizi erogati", art:"Art. 21.2.d + Art. 21.2.c", badge:"REQUISITO CONTRATTUALE", bc:"#f6ad55",
                  note:"Senza RTO/RPO documentati il cliente non può accettarti come fornitore critico",
                  opts:[{v:"si",l:"✅ Sì, BCP/DRP con RTO/RPO testati e documentati"},{v:"parziale",l:"⚠️ BCP esistente ma senza test periodici"},{v:"no",l:"❌ No BCP/DRP"}] },
                { id:"fq5", label:"Vulnerability assessment periodici e patch management con SLA per criticità alta/critica", art:"Art. 21.2.d + Art. 21.2.e", badge:"REQUISITO CONTRATTUALE", bc:"#f6ad55",
                  note:"Vulnerabilità sul tuo stack = superficie di attacco verso i sistemi del cliente NIS2",
                  opts:[{v:"si",l:"✅ Sì, VA periodici + SLA patch critiche documentati"},{v:"parziale",l:"⚠️ Patch applicate ma senza VA o SLA formalizzati"},{v:"no",l:"❌ No processo strutturato"}] },
                { id:"fq6", label:"Clausole contrattuali NIS2 nei contratti con clienti: SLA security, audit rights, notifica incidente", art:"Art. 21.2.d", badge:"REQUISITO CONTRATTUALE", bc:"#f6ad55",
                  note:"I clienti NIS2 sono obbligati per legge a inserire queste clausole — senza accordo rischiate entrambi",
                  opts:[{v:"si",l:"✅ Sì, clausole NIS2 presenti e aggiornate"},{v:"parziale",l:"⚠️ Clausole generiche, non specifiche NIS2"},{v:"no",l:"❌ No clausole security nei contratti"}] },
                { id:"fq7", label:"Offboarding: accessi ai sistemi del cliente revocati entro 24h dalla cessazione del rapporto", art:"Art. 21.2.d", badge:"BUONA PRATICA", bc:"#f6e05e",
                  opts:[{v:"si",l:"✅ Sì, processo automatizzato o <24h garantito"},{v:"parziale",l:"⚠️ Processo manuale, tempi variabili"},{v:"no",l:"❌ No processo formalizzato"}] },
                { id:"fq8", label:"Formazione cybersicurezza per il personale con accesso ai sistemi o dati del cliente", art:"Art. 21.2.d", badge:"BUONA PRATICA", bc:"#f6e05e",
                  opts:[{v:"si",l:"✅ Sì, formazione periodica documentata per ruolo"},{v:"saltuaria",l:"⚠️ Occasionale o senza tracciamento"},{v:"no",l:"❌ No"}] },
            ],
            "Fuori ambito": [
                { id:"q1", label:"Backup regolari, verificati e conservati off-site",               art:"Best practice ENISA",       badge:"CONSIGLIATO", bc:"#63b3ed",
                  opts:[{v:"si",l:"✅ Sì, regolari e verificati"},{v:"parziale",l:"⚠️ Presenti ma non verificati"},{v:"no",l:"❌ No"}] },
                { id:"q2", label:"Aggiornamenti software e patch di sicurezza applicati",           art:"Best practice ENISA",       badge:"CONSIGLIATO", bc:"#63b3ed",
                  opts:[{v:"si",l:"✅ Sì, regolari"},{v:"parziale",l:"⚠️ Solo sistemi critici"},{v:"no",l:"❌ No"}] },
                { id:"q3", label:"Formazione base sulla cybersicurezza per i dipendenti",           art:"Best practice ENISA",       badge:"CONSIGLIATO", bc:"#63b3ed",
                  opts:[{v:"si",l:"✅ Sì, almeno una volta"},{v:"no",l:"❌ No"}] },
            ]
        };

        function renderQuestionnaire() {
            var cat = window._nis2Category || 'Fuori ambito';
            var qs  = Q_CATALOG[cat] || Q_CATALOG['Fuori ambito'];
            var container = document.getElementById('questionnaire-container');
            var intro     = document.getElementById('q-intro');
            var catBadge  = document.getElementById('q-category-badge');

            var catStyles = {
                'Essenziale':      {bg:'rgba(252,129,129,0.1)', border:'rgba(252,129,129,0.4)', color:'#fc8181', text:'Soggetto Essenziale NIS2 — '+qs.length+' domande obbligatorie D.Lgs. 138/2024'},
                'Importante':      {bg:'rgba(246,224,94,0.08)', border:'rgba(246,224,94,0.4)',  color:'#f6e05e', text:'Soggetto Importante NIS2 — '+qs.length+' domande obbligatorie D.Lgs. 138/2024'},
                'Fornitore NIS2':  {bg:'rgba(156,135,226,0.10)', border:'rgba(156,135,226,0.4)', color:'#b794f4', text:'Fornitore di soggetti NIS2 — '+qs.length+' requisiti che il tuo cliente verificherà'},
                'Fuori ambito':    {bg:'rgba(99,179,237,0.08)', border:'rgba(99,179,237,0.3)',  color:'#63b3ed', text:'Fuori ambito NIS2 — '+qs.length+' domande di autovalutazione volontaria'},
            };
            var cs = catStyles[cat] || catStyles['Fuori ambito'];
            catBadge.style.display='block';
            catBadge.style.background=cs.bg; catBadge.style.border='1px solid '+cs.border;
            catBadge.innerHTML='<strong style="color:'+cs.color+';">'+cat+'</strong> &mdash; '+cs.text;

            var introMap = {
                'Essenziale':   'Questionario calibrato per <strong>soggetti essenziali</strong>: domande allineate agli obblighi legali del D.Lgs. 138/2024.',
                'Importante':   'Questionario calibrato per <strong>soggetti importanti</strong>: obblighi NIS2 con requisiti proporzionati alla categoria.',
                'Fornitore NIS2': 'Questionario per <strong>fornitori di soggetti NIS2</strong>: queste sono le domande che il tuo cliente ti farà. Ogni lacuna è un rischio di perdere il contratto o essere considerato responsabile in caso di incidente.',
                'Fuori ambito': 'La tua organizzazione non è soggetta agli obblighi NIS2. Le domande seguenti valutano la maturità di sicurezza come <strong>best practice volontarie</strong>.',
            };
            intro.innerHTML = introMap[cat] || introMap['Fuori ambito'];

            var html = '';
            qs.forEach(function(q, i) {
                html += '<div style="background:rgba(255,255,255,0.03);border:0.5px solid rgba(255,255,255,0.08);border-radius:8px;padding:14px 16px;margin-bottom:12px;">';
                html += '<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:10px;">';
                html += '<span style="background:rgba(255,255,255,0.08);color:#a0aec0;font-size:11px;padding:2px 7px;border-radius:4px;white-space:nowrap;">'+(i+1)+'/'+qs.length+'</span>';
                html += '<span style="background:'+q.bc+';color:#0a1628;font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;white-space:nowrap;">'+q.badge+'</span>';
                html += '<div><strong style="font-size:13px;color:#e2e8f0;">'+q.label+'</strong>';
                html += '<span style="font-size:11px;color:#718096;margin-left:8px;">'+q.art+'</span></div></div>';
                if (q.note) html += '<p style="font-size:11px;color:#9f7aea;margin:0 0 8px;font-style:italic;">💡 ' + q.note + '</p>';
                html += '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
                q.opts.forEach(function(o) {
                    html += '<label style="display:flex;align-items:center;gap:6px;cursor:pointer;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:6px 12px;font-size:13px;color:#cbd5e0;">';
                    html += '<input type="radio" name="'+q.id+'" value="'+o.v+'" style="accent-color:#63b3ed;">'+o.l+'</label>';
                });
                html += '</div></div>';
            });
            container.innerHTML = html;
        }

        function collectQuestions() {
            var cat = window._nis2Category || 'Fuori ambito';
            var qs  = Q_CATALOG[cat] || Q_CATALOG['Fuori ambito'];
            var result = {};
            qs.forEach(function(q) {
                var el = document.querySelector('input[name="'+q.id+'"]:checked');
                result[q.id] = el ? el.value : 'no';
            });
            return result;
        }

        function showPortableContact() { alert('Contatta il team Ichnobyte per la versione portable.'); }
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
            if (!email) { alert("Inserisci l\'indirizzo email aziendale"); return; }
            checkEmailDomain();
            var btn = document.getElementById("btn-otp");
            var status = document.getElementById("otp-status");
            btn.disabled = true; btn.textContent = "Invio in corso...";
            if (status) { status.style.display='block'; status.style.background='rgba(255,255,255,0.04)'; status.style.border='1px solid rgba(255,255,255,0.1)'; status.style.color='#a0aec0'; status.innerHTML='⏳ Invio codice OTP a <strong>' + email + '</strong>...'; }
            fetch("/api/send-otp", {
                method:"POST", headers:{"Content-Type":"application/json"},
                body: JSON.stringify({email: email})
            })
            .then(function(r){ return r.json(); })
            .then(function(d) {
                btn.disabled = false; btn.textContent = "Invia codice";
                if (d.success) {
                    var isDevMode = !!d.dev_code;
                    if (status) {
                        status.style.background = isDevMode ? 'rgba(246,173,85,0.08)' : 'rgba(56,161,105,0.08)';
                        status.style.border = isDevMode ? '1px solid rgba(246,173,85,0.3)' : '1px solid rgba(56,161,105,0.3)';
                        status.style.color = isDevMode ? '#f6ad55' : '#68d391';
                        status.innerHTML = isDevMode
                            ? '⚠️ <strong>Modalità sviluppo</strong> — SMTP non configurato. ' + d.message
                            : '✅ ' + d.message + ' Il codice scade in <strong>10 minuti</strong>.';
                        if (isDevMode) {
                            // Auto-compila il campo codice in dev mode
                            var otpField = document.getElementById("otp-code");
                            if (otpField) otpField.value = d.dev_code;
                        }
                    }
                    document.getElementById("otp-verify-section").style.display = "block";
                    // Avvia countdown 10 minuti
                    startOtpCountdown(600);
                } else {
                    if (status) {
                        status.style.background='rgba(252,129,129,0.08)';
                        status.style.border='1px solid rgba(252,129,129,0.3)';
                        status.style.color='#fc8181';
                        status.innerHTML = '❌ ' + (d.message || "Errore nell\'invio");
                    }
                }
            })
            .catch(function(){ btn.disabled=false; btn.textContent="Invia codice"; alert("Errore di rete"); });
        }

        var _otpTimer = null;
        function startOtpCountdown(seconds) {
            if (_otpTimer) clearInterval(_otpTimer);
            var el = document.getElementById("otp-countdown");
            if (!el) return;
            el.style.display = 'inline';
            function tick() {
                if (seconds <= 0) {
                    clearInterval(_otpTimer);
                    el.innerHTML = ' — <span style="color:#fc8181;">Codice scaduto</span>';
                    return;
                }
                var m = Math.floor(seconds / 60), s = seconds % 60;
                el.innerHTML = ' — scade in <strong>' + m + ':' + (s < 10 ? '0' : '') + s + '</strong>';
                seconds--;
            }
            tick();
            _otpTimer = setInterval(tick, 1000);
        }

        function verifyOTP() {
            var email = document.getElementById("email").value.trim();
            var code  = document.getElementById("otp-code").value.trim();
            if (!code) { alert("Inserisci il codice ricevuto"); return; }
            var btn = document.getElementById("btn-verify-otp");
            var status = document.getElementById("otp-verify-status");
            btn.disabled = true; btn.textContent = "Verifica...";
            fetch("/api/verify-otp", {
                method:"POST", headers:{"Content-Type":"application/json"},
                body: JSON.stringify({email: email, code: code})
            })
            .then(function(r){ return r.json(); })
            .then(function(d) {
                btn.disabled = false; btn.textContent = "Verifica";
                if (status) { status.style.display='block'; }
                if (d.valid) {
                    if (_otpTimer) clearInterval(_otpTimer);
                    if (status) {
                        status.style.background='rgba(56,161,105,0.08)';
                        status.style.border='1px solid rgba(56,161,105,0.3)';
                        status.style.color='#68d391';
                        status.innerHTML='✅ <strong>Email verificata.</strong> ' + (d.message || '');
                    }
                    otpVerified = true; checkBoth();
                    document.getElementById("goto-step3").disabled = !(dnsVerified && otpVerified);
                } else {
                    if (status) {
                        status.style.background='rgba(252,129,129,0.08)';
                        status.style.border='1px solid rgba(252,129,129,0.3)';
                        status.style.color='#fc8181';
                        status.innerHTML='❌ ' + (d.message || "Codice non corretto");
                    }
                }
            })
            .catch(function(){ btn.disabled=false; btn.textContent="Verifica"; });
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
            var btn = document.getElementById("btn-otp");
            btn.disabled = true; btn.textContent = "Invio...";
            fetch("/api/send-otp", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: email}) })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success) {
                    // otp-section handled by otp-verify-section;
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
            renderQuestionnaire();
            document.getElementById("step2").classList.add("hidden");
            document.getElementById("step3").classList.remove("hidden");
            document.getElementById("step3-indicator").classList.add("active");
            document.getElementById("step2-indicator").classList.add("completed");
        }

        function startFullScan() {
            var q = collectQuestions();
            var revenue = document.getElementById('revenue') ? document.getElementById('revenue').value : '';
            document.getElementById("step3").classList.add("hidden");
            var l = document.getElementById("loading"); if (l) l.style.display = "block";
            fetch("/api/scan", {
                method: "POST", headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    vat_number: document.getElementById("vat").value.trim(),
                    domain: document.getElementById("domain").value.trim(),
                    ateco: document.getElementById("ateco").value,
                    employees: document.getElementById("employees").value,
                    revenue: revenue,
                    nis2_category: window._nis2Category || "",
                    is_supplier: window._isSupplier || false,
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
            var cat = s.nis2_category ? s.nis2_category.category : "Fuori ambito";
            var catColor = cat === "Essenziale" ? "#fc8181" : cat === "Importante" ? "#f6e05e" : cat === "Fornitore NIS2" ? "#b794f4" : "#63b3ed";

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
                h += "<p style='font-size:12px;color:#a0aec0;margin-bottom:16px;'>Peso delle lacune in base alla categoria (<strong style='color:" + catColor + ";'>" + cat + "</strong>).</p>";

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

            // ---- NIS2 READINESS SUMMARY ----
            if (s.nis2_readiness) {
                var nr = s.nis2_readiness;

                h += "<div class='card'><h3>📊 NIS2 Readiness — Dettaglio punteggio</h3>";
                var catNote = cat === "Fornitore NIS2"
                    ? "Soggetto fuori ambito NIS2 come entità diretta, ma fornitore di soggetti Essenziali/Importanti (Art. 21.2.d)"
                    : "";
                h += "<p style='font-size:12px;color:#a0aec0;margin-bottom:" + (catNote ? "4px" : "14px") + ";'>Categoria: <strong style='color:" + catColor + ";'>" + cat + "</strong></p>";
                if (catNote) h += "<p style='font-size:11px;color:#9f7aea;margin-bottom:12px;font-style:italic;'>🔗 " + catNote + "</p>";

                function readBar(score, max, label, color) {
                    var pct = max > 0 ? Math.round(score/max*100) : 0;
                    return "<div style='margin-bottom:12px;'>" +
                        "<div style='display:flex;justify-content:space-between;font-size:12px;color:#a0aec0;margin-bottom:4px;'>" +
                        "<span>" + label + "</span><span style='color:#e2e8f0;font-weight:500;'>" + score + " / " + max + " pt (" + pct + "%)</span></div>" +
                        "<div style='height:8px;background:rgba(255,255,255,0.08);border-radius:4px;'>" +
                        "<div style='width:" + pct + "%;height:100%;border-radius:4px;background:" + color + ";transition:width .6s;'></div></div></div>";
                }

                h += readBar(nr.tech_score,  nr.tech_max,   "Controlli tecnici automatici", "#63b3ed");
                h += readBar(nr.quest_score, nr.quest_max,  "Governance e processi (questionario)", "#68d391");
                h += readBar(nr.ciso_score,  5,             "Responsabile sicurezza (CISO)", "#f6ad55");
                h += readBar(nr.email_score, 10,            "Verifica identità email/OTP", "#9f7aea");

                if (nr.critical_gaps && nr.critical_gaps.length > 0) {
                    h += "<div style='margin-top:12px;padding:10px 12px;background:rgba(252,129,129,0.08);border:1px solid rgba(252,129,129,0.3);border-radius:6px;'>";
                    h += "<p style='font-size:12px;font-weight:600;color:#fc8181;margin:0 0 6px;'>⚠️ Lacune critiche rilevate (" + nr.critical_gaps.length + "):</p>";
                    nr.critical_gaps.forEach(function(g){ h += "<p style='font-size:12px;color:#a0aec0;margin:2px 0;'>→ " + g + "</p>"; });
                    h += "</div>";
                }
                h += "</div>";
            }

            // ---- CTA VERSIONE PORTABLE — moduli specifici per gap ----
            var PORTABLE_MODULES = {
                "q1":  { icon:"📋", name:"Registrazione & Compliance ACN",   urgency:"LEGALE",
                         desc:"Checklist obblighi ACN, scadenzario registrazione, gestione documentale conforme D.Lgs. 138/2024" },
                "q2":  { icon:"👤", name:"CISO Virtuale",                     urgency:"GOVERNANCE",
                         desc:"Roadmap sicurezza, KPI, reportistica automatica per il CdA, mandato e responsabilità formalizzate" },
                "q3":  { icon:"🔍", name:"Analisi dei Rischi",                urgency:"LEGALE",
                         desc:"Metodologia ENISA guidata, asset inventory, valutazione minacce/impatto, report PDF NIS2-compliant" },
                "q4":  { icon:"🚨", name:"Incident Management",              urgency:"LEGALE",
                         desc:"Workflow notifica ACN 24h/72h, template pre-compilati, registro incidenti, escalation automatica" },
                "q5":  { icon:"🔄", name:"Business Continuity",              urgency:"OPERATIVO",
                         desc:"Template BCP, scenari di crisi, pianificazione e log esercitazioni, RTO/RPO documentati" },
                "q6":  { icon:"🔐", name:"Access Control & Crittografia",    urgency:"TECNICO",
                         desc:"Verifica MFA deployment, policy password, cifratura endpoint e dati a riposo, audit accessi privilegiati" },
                "q7":  { icon:"🛡️", name:"Patch & Vulnerability Management", urgency:"TECNICO",
                         desc:"Inventario asset software, SLA patch per criticità, registro CVE, remediation tracking" },
                "q8":  { icon:"🔗", name:"Gestione Fornitori & Supply Chain", urgency:"LEGALE",
                         desc:"Questionario sicurezza fornitori, scoring supply chain, contratti con clausole NIS2, registro terze parti critiche" },
                "q9":  { icon:"🎓", name:"Formazione & Awareness",           urgency:"OPERATIVO",
                         desc:"Moduli e-learning NIS2, simulazioni phishing, test conoscenza, tracciamento e attestati di completamento" },
                "q10": { icon:"📄", name:"Audit & Penetration Test",         urgency:"CONFORMITÀ",
                         desc:"Gap analysis NIS2/ISO 27001, roadmap certificazione, gestione report pen-test, remediation plan" },
            };

            // Portable modules for Fornitore NIS2
            var PORTABLE_MODULES_SUPPLIER = {
                "fq1": { icon:"🔐", name:"Accesso Remoto Sicuro & MFA",        urgency:"URGENTE",
                         desc:"Verifica MFA su tutti gli accessi al cliente, accessi nominativi tracciati, log conservati, revoca automatica accessi inattivi" },
                "fq2": { icon:"👤", name:"PAM — Privileged Access Management", urgency:"URGENTE",
                         desc:"Separazione account admin/standard, least privilege, session recording accessi privilegiati, approvazione workflow per accessi critici" },
                "fq3": { icon:"🚨", name:"Incident Response per Fornitori",    urgency:"URGENTE",
                         desc:"Template IRP fornitore NIS2, workflow notifica cliente con SLA 24h, escalation automatica, registro incidenti condiviso con cliente" },
                "fq4": { icon:"🔄", name:"BCP/DRP con RTO-RPO documentati",    urgency:"CONTRATTUALE",
                         desc:"Template BCP specifico per servizi erogati al cliente, definizione RTO/RPO, log test DR periodici, evidenze condivisibili in audit" },
                "fq5": { icon:"🛡️", name:"Vulnerability & Patch Management",   urgency:"CONTRATTUALE",
                         desc:"Scan VA periodici, SLA patch critiche <72h, remediation tracking con evidenza, report condivisibile con cliente per audit supply chain" },
                "fq6": { icon:"📄", name:"Template Clausole NIS2",             urgency:"CONTRATTUALE",
                         desc:"Clausole security standard NIS2-compliant, SLA sicurezza, diritti di audit, obblighi notifica incidente — pronte per i contratti con clienti NIS2" },
                "fq7": { icon:"🔑", name:"Offboarding & Gestione Accessi",     urgency:"OPERATIVO",
                         desc:"Processo revoca accessi <24h, registro utenti attivi per cliente, audit automatico account, notifica cliente su variazioni" },
                "fq8": { icon:"🎓", name:"Formazione per Fornitori NIS2",      urgency:"OPERATIVO",
                         desc:"Moduli formazione specifici per tecnici con accesso a clienti NIS2, simulazioni phishing, attestati condivisibili in audit supply chain" },
            };

            var urgencyColor = { "LEGALE":"#fc8181", "GOVERNANCE":"#f6ad55", "TECNICO":"#63b3ed", "OPERATIVO":"#68d391", "CONFORMITÀ":"#9f7aea", "URGENTE":"#fc8181", "CONTRATTUALE":"#f6ad55" };

            var gaps = s.questionnaire_gaps || [];
            var cat  = s.nis2_category ? s.nis2_category.category : "Fuori ambito";
            var critCount = gaps.filter(function(g){ return g.weight === "CRITICO"; }).length;
            var altoCount = gaps.filter(function(g){ return g.weight === "ALTO"; }).length;

            // Use supplier modules if Fornitore NIS2
            var modMap = (cat === 'Fornitore NIS2') ? PORTABLE_MODULES_SUPPLIER : PORTABLE_MODULES;

            // Collect modules needed for actual gaps
            var neededModules = [];
            var seenKeys = {};
            gaps.forEach(function(g) {
                if (!modMap[g.key] || seenKeys[g.key]) return;
                seenKeys[g.key] = true;
                neededModules.push({ mod: modMap[g.key], gap: g });
            });

            // Alert level
            var alertBg, alertBorder, alertIcon, alertTitle, alertIntro;
            if (critCount >= 2 && cat === "Essenziale") {
                alertBg="rgba(252,129,129,0.1)"; alertBorder="rgba(252,129,129,0.55)";
                alertIcon="🚨"; alertTitle="Esposizione legale immediata — " + critCount + " obblighi NIS2 non rispettati";
                alertIntro="Come soggetto <strong>Essenziale</strong>, la tua organizzazione è già soggetta agli obblighi del D.Lgs. 138/2024. I gap critici rilevati espongono a <strong>sanzioni fino a 10 milioni di € o il 2% del fatturato globale</strong> e a responsabilità penale degli organi direttivi in caso di incidente.";
            } else if (critCount >= 1 || (cat === "Essenziale" && altoCount >= 2)) {
                alertBg="rgba(246,173,85,0.1)"; alertBorder="rgba(246,173,85,0.5)";
                alertIcon="⚠️"; alertTitle="Intervento prioritario richiesto";
                alertIntro="Sono presenti <strong>" + (critCount + altoCount) + " lacune di governance</strong> che devono essere colmate prima del prossimo audit o incidente. I moduli seguenti risolvono esattamente i gap rilevati.";
            } else if (cat === "Fornitore NIS2") {
                alertBg="rgba(156,135,226,0.12)"; alertBorder="rgba(156,135,226,0.5)";
                alertIcon="🔗"; alertTitle="Fornitore NIS2 — il tuo cliente verificherà questi requisiti";
                alertIntro="Anche se non sei direttamente soggetto NIS2, i tuoi clienti Essenziali o Importanti sono <strong>obbligati dall\'Art. 21.2.d</strong> a verificare la tua sicurezza. Ogni lacuna è un rischio concreto di <strong>perdere il contratto</strong> o essere ritenuto co-responsabile in caso di incidente.";
            } else if (cat === "Fuori ambito") {
                alertBg="rgba(99,179,237,0.08)"; alertBorder="rgba(99,179,237,0.3)";
                alertIcon="💡"; alertTitle="NIS2 non obbligatorio — ma i rischi cyber sono reali";
                alertIntro="La tua organizzazione non rientra nell'ambito NIS2. Tuttavia un attacco ransomware o una violazione di dati può colpire qualsiasi azienda. I moduli seguenti rafforzano la postura di sicurezza come misura preventiva.";
            } else {
                alertBg="rgba(99,179,237,0.08)"; alertBorder="rgba(99,179,237,0.3)";
                alertIcon="🔍"; alertTitle="Completare la conformità NIS2";
                alertIntro="Il Quick Scan copre la superficie pubblica. I gap di processo e governance rilevati richiedono strumenti dedicati per essere risolti strutturalmente.";
            }

            if (neededModules.length > 0) {
                h += "<div style='background:" + alertBg + ";border:2px solid " + alertBorder + ";border-radius:12px;padding:22px;margin-top:20px;'>";
                h += "<h3 style='color:#e2e8f0;margin-top:0;font-size:17px;'>" + alertIcon + " " + alertTitle + "</h3>";
                h += "<p style='font-size:13px;color:#cbd5e0;margin-bottom:16px;line-height:1.6;'>" + alertIntro + "</p>";

                h += "<p style='font-size:12px;font-weight:700;color:#a0aec0;text-transform:uppercase;letter-spacing:.06em;margin:0 0 10px;'>Moduli disponibili nella versione portable:</p>";

                neededModules.forEach(function(item) {
                    var m = item.mod; var g = item.gap;
                    var uc = urgencyColor[m.urgency] || "#a0aec0";
                    var gapLabel = g.weight === "CRITICO" ? "🔴 CRITICO" : g.weight === "ALTO" ? "🟠 ALTO" : "🟡 MEDIO";
                    h += "<div style='background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:12px 14px;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start;'>";
                    h += "<span style='font-size:22px;line-height:1;'>" + m.icon + "</span>";
                    h += "<div style='flex:1;'>";
                    h += "<div style='display:flex;align-items:center;gap:8px;margin-bottom:4px;'>";
                    h += "<strong style='font-size:13px;color:#e2e8f0;'>" + m.name + "</strong>";
                    h += "<span style='font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;background:" + uc + ";color:#0a1628;'>" + m.urgency + "</span>";
                    h += "<span style='font-size:10px;color:#718096;margin-left:auto;'>" + gapLabel + "</span></div>";
                    h += "<p style='font-size:12px;color:#a0aec0;margin:0;line-height:1.5;'>" + m.desc + "</p>";
                    h += "<p style='font-size:11px;color:#718096;margin:4px 0 0;font-style:italic;'>Colma la lacuna: " + g.label + "</p>";
                    h += "</div></div>";
                });

                h += "<div style='margin-top:16px;padding-top:14px;border-top:1px solid rgba(255,255,255,0.08);display:flex;align-items:center;justify-content:space-between;flex-wrap:gap;'>";
                h += "<div><p style='font-size:12px;color:#68d391;font-weight:600;margin:0;'>✅ Versione portable include anche:</p>";
                h += "<p style='font-size:11px;color:#718096;margin:3px 0 0;'>Scan rete interna • endpoint • BitLocker • porte • firewall • antivirus</p></div>";
                h += "<a href=\'#\' onclick=\'showPortableContact()\' style=\'display:inline-block;padding:10px 20px;background:#185FA5;color:#fff;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;\'>⬇️ Richiedi la versione portable</a>";
                h += "</div></div>";
            }
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

# ─────────────────────────────────────────────
# Helper: invio OTP via SMTP
# ─────────────────────────────────────────────
def _smtp_send(to_email, code):
    """
    Invia OTP via SMTP.
    Configura le variabili d'ambiente:
      SMTP_HOST     (default: smtp.gmail.com)
      SMTP_PORT     (default: 587  — usa 465 per SSL diretto)
      SMTP_USER     mittente (es. tuamail@gmail.com)
      SMTP_PASSWORD app-password Gmail o password SMTP
      SMTP_FROM     nome mittente opzionale
    """
    host  = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    port  = int(os.environ.get('SMTP_PORT', '587'))
    user  = os.environ.get('SMTP_USER', '')
    pwd   = os.environ.get('SMTP_PASSWORD', '')
    frm   = os.environ.get('SMTP_FROM', user)

    if not user or not pwd:
        raise EnvironmentError("SMTP non configurato — impostare SMTP_USER e SMTP_PASSWORD")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Codice di verifica — NIS2 Compliance Tool'
    msg['From']    = f'NIS2 Tool <{frm}>'
    msg['To']      = to_email

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;
                background:#0d1b2a;border-radius:12px;color:#e2e8f0;">
      <h2 style="color:#63b3ed;margin-top:0;">NIS2 Compliance Tool</h2>
      <p style="color:#a0aec0;font-size:14px;">Il tuo codice di verifica è:</p>
      <div style="font-size:40px;font-weight:700;letter-spacing:12px;color:#68d391;
                  background:rgba(104,211,145,0.1);border-radius:8px;padding:20px;
                  text-align:center;margin:20px 0;">{code}</div>
      <p style="color:#718096;font-size:12px;">
        Il codice scade tra <strong>10 minuti</strong>.<br>
        Se non hai richiesto questo codice ignora questa email.
      </p>
    </div>"""

    msg.attach(MIMEText(html_body, 'html'))

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=10) as srv:
            srv.login(user, pwd)
            srv.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=10) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(user, pwd)
            srv.send_message(msg)


@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    email = request.json.get('email', '').strip().lower()
    if not email or '@' not in email:
        return jsonify({"success": False, "message": "Indirizzo email non valido"})

    # Rate limiting: max 3 richieste per email ogni 15 minuti
    existing = verification_codes.get(email, {})
    if isinstance(existing, dict):
        req_count = existing.get('req_count', 0)
        req_time  = existing.get('req_time', 0)
        if req_count >= 3 and time.time() - req_time < 900:
            return jsonify({"success": False,
                            "message": "Troppi tentativi. Attendi 15 minuti."})

    code    = ''.join(random.choices(string.digits, k=6))
    expiry  = time.time() + 600   # 10 minuti
    req_cnt = (existing.get('req_count', 0) + 1) if isinstance(existing, dict) else 1
    verification_codes[email] = {
        "code":      code,
        "expiry":    expiry,
        "attempts":  0,
        "req_count": req_cnt,
        "req_time":  time.time()
    }

    # Tentativo di invio SMTP
    smtp_configured = bool(os.environ.get('SMTP_USER') and os.environ.get('SMTP_PASSWORD'))
    if smtp_configured:
        try:
            _smtp_send(email, code)
            return jsonify({"success": True,
                            "message": f"Codice inviato a {email}. Controlla la casella (e lo spam)."})
        except Exception as e:
            # Non esponiamo dettagli dell'errore SMTP all'esterno
            print(f"[OTP] Errore SMTP: {e}")
            return jsonify({"success": False,
                            "message": "Errore durante l'invio. Verificare la configurazione SMTP."})
    else:
        # Modalità sviluppo: codice restituito nella risposta
        # In produzione configurare SMTP_USER e SMTP_PASSWORD
        print(f"[DEV] OTP per {email}: {code}")
        return jsonify({"success": True,
                        "message": f"[Modalità sviluppo — SMTP non configurato] Codice: {code}",
                        "dev_code": code})


@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    email = request.json.get('email', '').strip().lower()
    code  = request.json.get('code', '').strip()

    stored = verification_codes.get(email)
    if not isinstance(stored, dict):
        return jsonify({"valid": False, "message": "Nessun codice attivo per questa email. Richiedi un nuovo codice."})

    if time.time() > stored.get("expiry", 0):
        verification_codes.pop(email, None)
        return jsonify({"valid": False, "message": "Codice scaduto (10 min). Richiedi un nuovo codice."})

    stored["attempts"] = stored.get("attempts", 0) + 1
    if stored["attempts"] > 5:
        verification_codes.pop(email, None)
        return jsonify({"valid": False, "message": "Troppi tentativi errati. Richiedi un nuovo codice."})

    if stored["code"] == code:
        verification_codes.pop(email, None)   # invalida dopo l'uso
        return jsonify({"valid": True, "message": "Email verificata correttamente."})

    remaining = 5 - stored["attempts"]
    return jsonify({"valid": False,
                    "message": f"Codice non corretto. Tentativi rimanenti: {remaining}"})


@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    company_data = lookup_company(data.get('vat_number', ''))
    if company_data is None:
        company_data = {"name": "Partita IVA non trovata", "ateco": data.get('ateco','N/D'), "employees": data.get('employees','N/D'), "revenue": data.get('revenue',''), "is_supplier": bool(data.get('is_supplier', False)), "address": "N/D", "status": "error"}
    else:
        company_data["ateco"]       = data.get('ateco', 'N/D')
        company_data["employees"]   = data.get('employees', 'N/D')
        company_data["revenue"]     = data.get('revenue', '')
        company_data["is_supplier"] = bool(data.get('is_supplier', False))
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