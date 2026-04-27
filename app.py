from flask import Flask, render_template_string, request, jsonify
from company_lookup import lookup_company
from domain_scanner import scan_domain
from scoring import calculate_nis2_score
import random
import string
import smtplib
import dns.resolver
from email.mime.text import MIMEText

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = 'nis2-quick-scan-secret-key-change-me'

verification_codes = {}

SENDGRID_SERVER = "smtp.sendgrid.net"
SENDGRID_PORT = 587
SENDGRID_USERNAME = "apikey"
SENDGRID_API_KEY = "LA_TUA_API_KEY_SENDGRID"
SENDGRID_FROM_EMAIL = "gfarigu@gmail.com"
SENDGRID_FROM_NAME = "NIS2 Compliance Tool"

HTML_TEMPLATE = """
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
        .top-bar-title { font-size: 22px; font-weight: 700; color: #ffffff; margin: 0; letter-spacing: 0.5px; white-space: nowrap; }
        .top-bar-title span { color: #63b3ed; font-weight: 400; }
        .top-bar-slogan { font-size: 13px; color: #a0aec0; margin: 3px 0 0 0; font-style: italic; letter-spacing: 0.3px; }
        .main-container { position: relative; z-index: 1; max-width: 900px; margin: 0 auto; padding: 40px 20px 50px 20px; }
        .subtitle { color: #a0aec0; margin: 10px 0 25px 0; font-size: 15px; }
        .card { background: rgba(15, 27, 45, 0.9); border: 1px solid rgba(43,108,176,0.3); border-radius: 10px; padding: 25px; margin: 20px 0; backdrop-filter: blur(5px); }
        button { background: #2b6cb0; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 15px; font-weight: 600; transition: background 0.2s; }
        button:hover { background: #1d4ed8; }
        button:disabled { background: #4a5568; cursor: not-allowed; }
        .btn-full { width: 100%; padding: 15px 30px; font-size: 16px; }
        .btn-small { width: auto; padding: 10px 20px; font-size: 14px; margin-top: 5px; }
        .btn-outline { background: transparent; border: 2px solid #2b6cb0; color: #2b6cb0; }
        .btn-outline:hover { background: #2b6cb0; color: white; }
        input, select { padding: 12px; border: 1px solid rgba(43,108,176,0.4); border-radius: 6px; width: 100%; font-size: 16px; margin-bottom: 10px; background: rgba(15,27,45,0.8); color: #e2e8f0; }
        input::placeholder { color: #718096; }
        select { color: #e2e8f0; }
        select option { background: #1a365d; color: #e2e8f0; }
        label { font-weight: 600; display: block; margin-bottom: 5px; color: #cbd5e0; font-size: 14px; }
        small { font-size: 12px; line-height: 1.4; }
        .ok { color: #68d391; font-weight: bold; }
        .warning { color: #f6e05e; font-weight: bold; }
        .error { color: #fc8181; font-weight: bold; }
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
        .badge-gray { background: #4a5568; color: #cbd5e0; }
        .step-indicator { display: flex; justify-content: space-between; margin-bottom: 25px; }
        .step { text-align: center; flex: 1; position: relative; }
        .step-circle { width: 35px; height: 35px; border-radius: 50%; background: rgba(43,108,176,0.3); color: #cbd5e0; display: flex; align-items: center; justify-content: center; margin: 0 auto 5px; font-weight: bold; font-size: 15px; }
        .step.active .step-circle { background: #2b6cb0; color: white; }
        .step.completed .step-circle { background: #38a169; color: white; }
        .step-label { font-size: 12px; color: #a0aec0; font-weight: 500; }
        .hidden { display: none; }
        .question-group { margin-bottom: 18px; }
        .radio-group { display: flex; gap: 25px; margin-top: 6px; }
        .radio-group label { font-weight: normal; cursor: pointer; color: #cbd5e0; }
        .verification-section { margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid rgba(43,108,176,0.2); }
        .verification-section:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
        .section-title { font-size: 16px; font-weight: 700; color: #63b3ed; margin-bottom: 12px; }
        .otp-input { width: 150px !important; display: inline-block; margin-right: 10px; }
        .verified-badge { display: inline-block; background: #22543d; color: #68d391; padding: 5px 12px; border-radius: 12px; font-size: 13px; font-weight: 600; }
        .dns-verified { display: inline-block; background: rgba(43,108,176,0.3); color: #bee3f8; padding: 5px 12px; border-radius: 12px; font-size: 13px; font-weight: 600; }
        .network-info { background: rgba(43,108,176,0.15); border: 1px solid rgba(43,108,176,0.4); border-radius: 8px; padding: 12px 15px; margin-bottom: 15px; }
        .network-info .network-type { font-weight: 700; }
        .network-corporate { color: #68d391; }
        .network-public { color: #f6e05e; }
    </style>
</head>
<body>
    <div class="top-bar">
        <img src="/logo.png" alt="Ichnobyte">
        <div class="top-bar-text">
            <h1 class="top-bar-title">Ichnobyte - <span>NIS2 Compliance Tool</span></h1>
            <p class="top-bar-slogan">Misura la tua conformità. Riduci il rischio. Anticipa la normativa.</p>
        </div>
        <div class="badge badge-blue">SUPPLY CHAIN VERIFICATION</div>
    </div>

    <div class="main-container">
        <p class="subtitle">Inserisci Partita IVA, dominio aziendale e verifica automaticamente la conformita alla Direttiva NIS2.</p>

        <div class="step-indicator">
            <div class="step" id="step1-indicator"><div class="step-circle">1</div><div class="step-label">Dati Aziendali</div></div>
            <div class="step" id="step2-indicator"><div class="step-circle">2</div><div class="step-label">Verifica Email</div></div>
            <div class="step" id="step3-indicator"><div class="step-circle">3</div><div class="step-label">Questionario</div></div>
            <div class="step" id="step4-indicator"><div class="step-circle">4</div><div class="step-label">Risultati</div></div>
        </div>

        <!-- STEP 1: DATI AZIENDALI (senza domanda CISO) -->
        <div class="card" id="step1">
            <h3>Dati Aziendali</h3>
            
            <label>Partita IVA</label>
            <input type="text" id="vat" placeholder="es. 12345678901">
            
            <label>Dominio aziendale (per scan sito web e DNS)</label>
            <input type="text" id="domain" placeholder="es. azienda.it">
            <small style="color:#a0aec0; display:block; margin-top:-5px; margin-bottom:10px;">
                Su questo dominio verranno eseguiti i controlli del sito web e dei record DNS.
            </small>

            <!-- Rilevamento automatico rete -->
            <div class="network-info" id="network-info" style="display:none;">
                <p><strong>Rete rilevata:</strong> <span id="network-type"></span></p>
                <p style="font-size:13px; color:#a0aec0;" id="network-message"></p>
            </div>
            
            <label>Indirizzo IP pubblico <span style="color:#63b3ed; font-weight:normal; font-size:12px;">- Rilevato automaticamente</span></label>
            <input type="text" id="public-ip" placeholder="Rilevamento in corso...">
            <small style="color:#a0aec0; display:block; margin-top:-5px; margin-bottom:15px;">
                <span id="ip-hint">Rilevamento della rete in corso...</span>
            </small>
            
            <label>Settore (codice ATECO principale)</label>
            <select id="ateco">
                <option value="">Seleziona il tuo settore...</option>
                <option value="35">Energia</option><option value="49">Trasporti</option><option value="86">Sanita</option>
                <option value="61">ICT - Telecomunicazioni</option><option value="62">ICT - Servizi Digitali</option>
                <option value="63">ICT - Portali e Data Center</option><option value="64">Finanza e Banche</option>
                <option value="84">Pubblica Amministrazione</option><option value="36">Acqua e Rifiuti</option>
                <option value="20">Chimico e Farmaceutico</option><option value="10">Alimentare</option>
                <option value="25">Metalmeccanico</option><option value="58">Editoria e Media</option>
                <option value="altro">Altro settore</option>
            </select>
            
            <label>Numero dipendenti</label>
            <select id="employees">
                <option value="">Seleziona...</option>
                <option value="1-10">1-10</option><option value="11-50">11-50</option>
                <option value="51-250">51-250</option><option value="250+">Oltre 250</option>
            </select>
            
            <button onclick="goToStep2()">Avanti</button>
        </div>

        <!-- STEP 2: VERIFICA EMAIL -->
        <div class="card hidden" id="step2">
            <h3>Verifica dell'Infrastruttura di Posta Elettronica</h3>
            <p style="color:#a0aec0; margin-bottom:20px;">Questa verifica è composta da due test indipendenti per valutare la conformità NIS2 della tua email aziendale (Art. 21).</p>
            <div class="verification-section">
                <div class="section-title">1. Test Tecnici dell'Infrastruttura di Posta</div>
                <p style="color:#a0aec0; font-size:14px; margin-bottom:10px;">Analizza in automatico i record DNS e la configurazione di sicurezza del server di posta.<br><strong>Non viene inviata alcuna email.</strong></p>
                <label>Email aziendale da analizzare</label>
                <input type="email" id="email" placeholder="es. sicurezza@azienda.it">
                <button class="btn-small" onclick="verifyDNS()" id="btn-dns">Esegui Test Tecnici</button>
                <div id="dns-result"></div>
            </div>
            <div class="verification-section">
                <div class="section-title">2. Conferma dell'Identità Digitale (Codice OTP)</div>
                <p style="color:#a0aec0; font-size:14px; margin-bottom:10px;">Verifica che hai accesso reale alla casella email. Riceverai un codice monouso.</p>
                <button class="btn-small btn-outline" onclick="sendOTP()" id="btn-otp-send">Ricevi Codice di Verifica</button>
                <div id="otp-section" class="hidden" style="margin-top:15px;">
                    <input type="text" id="otp-code" class="otp-input" placeholder="Codice di 6 cifre">
                    <button class="btn-small" onclick="verifyOTP()" id="btn-otp-verify">Conferma Codice</button>
                </div>
                <div id="otp-result"></div>
            </div>
            <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid rgba(43,108,176,0.3); text-align: center; color: #a0aec0;">
                <small>Entrambi i test devono essere superati per procedere con la valutazione NIS2 completa.</small>
            </div>
            <button onclick="goToStep3()" id="goto-step3" disabled class="btn-full" style="margin-top:15px;">Prosegui con il Questionario</button>
        </div>

        <!-- STEP 3: QUESTIONARIO (con domanda CISO integrata) -->
        <div class="card hidden" id="step3">
            <h3>Questionario di Conformità NIS2</h3>
            <p style="color:#a0aec0; margin-bottom:25px;">Le seguenti domande coprono i requisiti fondamentali del <strong>D.Lgs. 138/2024</strong> (recepimento Direttiva NIS2).</p>
            
            <h4 style="color:#63b3ed; border-bottom:1px solid rgba(43,108,176,0.3); padding-bottom:8px; margin-bottom:15px;">A. REQUISITI ORGANIZZATIVI E REGISTRAZIONE</h4>
            
            <div class="question-group">
                <label>1. La vostra organizzazione ha completato la registrazione al portale ACN (art. 7 D.Lgs. 138/2024)?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q1" value="si"> Sì, registrazione completata</label>
                    <label><input type="radio" name="q1" value="no"> Non ancora</label>
                    <label><input type="radio" name="q1" value="non_so"> Non so se siamo obbligati</label>
                </div>
            </div>
            <div class="question-group">
                <label>2. Avete designato un Punto di Contatto (PdC) per la cybersicurezza?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q2" value="si"> Sì, abbiamo un PdC designato</label>
                    <label><input type="radio" name="q2" value="no"> No, non ancora</label>
                </div>
            </div>
            <div class="question-group">
                <label>3. La vostra azienda ha un CISO o un referente per la sicurezza informatica chiaramente identificato?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q3" value="si_interno"> Sì, CISO interno dedicato</label>
                    <label><input type="radio" name="q3" value="si_esterno"> Sì, consulente/RdP esterno</label>
                    <label><input type="radio" name="q3" value="no"> No, nessun referente</label>
                </div>
            </div>

            <h4 style="color:#63b3ed; border-bottom:1px solid rgba(43,108,176,0.3); padding-bottom:8px; margin-bottom:15px; margin-top:25px;">B. MISURE TECNICHE E ORGANIZZATIVE (Art. 21)</h4>
            
            <div class="question-group">
                <label>4. Disponete di un'analisi dei rischi documentata e aggiornata?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q4" value="si"> Sì, documentata e revisionata</label>
                    <label><input type="radio" name="q4" value="parziale"> In fase di elaborazione</label>
                    <label><input type="radio" name="q4" value="no"> No, nessuna analisi formale</label>
                </div>
            </div>
            <div class="question-group">
                <label>5. Avete un sistema di gestione e notifica incidenti (segnalazione ACN entro 24 ore)?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q5" value="si"> Sì, procedura definita e testata</label>
                    <label><input type="radio" name="q5" value="parziale"> Procedura esistente ma non testata</label>
                    <label><input type="radio" name="q5" value="no"> No, nessuna procedura formale</label>
                </div>
            </div>
            <div class="question-group">
                <label>6. Applicate politiche di sicurezza per accessi (MFA, privilegi minimi) e protezione dati (backup, cifratura)?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q6" value="si"> Sì, implementate e verificate</label>
                    <label><input type="radio" name="q6" value="parziale"> Solo alcune misure implementate</label>
                    <label><input type="radio" name="q6" value="no"> No, nessuna politica formale</label>
                </div>
            </div>
            <div class="question-group">
                <label>7. Avete un processo di patch management e gestione vulnerabilità?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q7" value="si"> Sì, automatizzato e verificato</label>
                    <label><input type="radio" name="q7" value="parziale"> Aggiornamenti manuali, nessun monitoraggio</label>
                    <label><input type="radio" name="q7" value="no"> No, nessun processo definito</label>
                </div>
            </div>

            <h4 style="color:#63b3ed; border-bottom:1px solid rgba(43,108,176,0.3); padding-bottom:8px; margin-bottom:15px; margin-top:25px;">C. SUPPLY CHAIN, FORMAZIONE E CERTIFICAZIONI</h4>
            
            <div class="question-group">
                <label>8. Verificate formalmente la sicurezza informatica dei vostri fornitori?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q8" value="si"> Sì, con audit e questionari periodici</label>
                    <label><input type="radio" name="q8" value="parziale"> Solo per i fornitori più critici</label>
                    <label><input type="radio" name="q8" value="no"> No, nessuna verifica</label>
                </div>
            </div>
            <div class="question-group">
                <label>9. Effettuate formazione periodica sulla cybersicurezza per dipendenti e organi di amministrazione?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q9" value="si"> Sì, formazione annuale obbligatoria</label>
                    <label><input type="radio" name="q9" value="saltuaria"> Formazione saltuaria o solo iniziale</label>
                    <label><input type="radio" name="q9" value="no"> No, nessuna formazione specifica</label>
                </div>
            </div>
            <div class="question-group">
                <label>10. Possedete certificazioni di sicurezza riconosciute (ISO 27001, ISO 22301, SOC2)?</label>
                <div class="radio-group">
                    <label><input type="radio" name="q10" value="iso27001"> ISO 27001</label>
                    <label><input type="radio" name="q10" value="altra"> Altra certificazione</label>
                    <label><input type="radio" name="q10" value="in_corso"> In corso di ottenimento</label>
                    <label><input type="radio" name="q10" value="no"> Nessuna certificazione</label>
                </div>
            </div>
            
            <div style="text-align:center; margin-top:25px;">
                <button onclick="startFullScan()" class="btn-full" style="width:80%;">Avvia Quick Scan NIS2 Completo</button>
                <p style="color:#718096; font-size:12px; margin-top:10px;">Le tue risposte saranno incrociate con gli scan tecnici automatici.</p>
            </div>
        </div>

        <div id="loading" style="display:none; text-align:center; padding:30px;">
            <p style="font-size:18px; color:#e2e8f0;">Scansione in corso...</p>
            <p style="font-size:14px;color:#a0aec0;">Analisi dei dati camerali, scan tecnici e calcolo del punteggio.</p>
        </div>

        <div id="results" class="result"></div>
    </div>

    <script>
        // Variabili globali
        var dnsVerified = false;
        var otpVerified = false;
        var emailResults = null;
        var isCorporateNetwork = false;
        var detectedIP = '';

               // Rilevamento automatico IP (versione semplificata)
        (function() {
            var ipField = document.getElementById('public-ip');
            var ipHint = document.getElementById('ip-hint');
            var networkInfo = document.getElementById('network-info');
            var networkType = document.getElementById('network-type');
            var networkMessage = document.getElementById('network-message');
            
            // Se gli elementi non esistono, esci silenziosamente
            if (!ipField) return;
            
            // Timeout di sicurezza: dopo 4 secondi, chiedi inserimento manuale
            var timeout = setTimeout(function() {
                if (ipField.value === '' || ipField.value === 'Rilevamento in corso...') {
                    ipField.value = '';
                    ipField.placeholder = 'Inserisci IP pubblico aziendale';
                    if (ipHint) ipHint.innerHTML = '⚠️ Rilevamento automatico non disponibile. Inserisci l\\'IP manualmente (cerca "mio IP" su Google dalla rete aziendale).';
                    if (networkInfo) networkInfo.style.display = 'block';
                    if (networkType) networkType.innerHTML = '<span class="badge-gray">🌐 Inserimento manuale richiesto</span>';
                    if (networkMessage) networkMessage.innerHTML = 'Non è stato possibile rilevare automaticamente l\\'IP. Inseriscilo manualmente per procedere.';
                }
            }, 4000);
            
            // Prova a rilevare l'IP
            try {
                fetch('https://api.ipify.org?format=json')
                    .then(function(resp) { return resp.json(); })
                    .then(function(data) {
                        if (data && data.ip) {
                            clearTimeout(timeout);
                            detectedIP = data.ip;
                            ipField.value = detectedIP;
                            ipField.style.borderColor = 'rgba(43,108,176,0.6)';
                            if (ipHint) ipHint.innerHTML = '✅ IP rilevato: ' + detectedIP + '. Se sei in ufficio o in VPN, puoi procedere.';
                            if (networkInfo) networkInfo.style.display = 'block';
                            if (networkType) networkType.innerHTML = '<span class="badge-blue">🌐 IP Pubblico Rilevato</span>';
                            if (networkMessage) networkMessage.innerHTML = 'IP: ' + detectedIP + '. Gli scan infrastrutturali verranno eseguiti su questo indirizzo. Se sei in smart working, sostituiscilo con l\\'IP della rete aziendale.';
                            isCorporateNetwork = false; // Per sicurezza, assumiamo rete non aziendale
                        }
                    })
                    .catch(function() {
                        // Lasciamo scattare il timeout
                    });
            } catch(e) {
                // Lasciamo scattare il timeout
            }
        })();

        function goToStep2() {
            var vat = document.getElementById("vat").value.trim();
            var domain = document.getElementById("domain").value.trim();
            var ateco = document.getElementById("ateco").value;
            var employees = document.getElementById("employees").value;
            if (!vat || !domain || !ateco || !employees) {
                alert("Compila tutti i campi prima di proseguire");
                return;
            }
            document.getElementById("step1").classList.add("hidden");
            document.getElementById("step2").classList.remove("hidden");
            document.getElementById("step2-indicator").classList.add("active");
            document.getElementById("step1-indicator").classList.add("completed");
        }

        function checkBothTests() {
            if (dnsVerified && otpVerified) {
                document.getElementById("goto-step3").disabled = false;
            }
        }

        function verifyDNS() {
            var email = document.getElementById("email").value.trim();
            if (!email) { alert("Inserisci un indirizzo email da analizzare"); return; }
            var btn = document.getElementById("btn-dns");
            btn.disabled = true; btn.textContent = "Analisi in corso...";
            fetch("/api/verify-dns", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({email: email})
            })
            .then(function(resp) { return resp.json(); })
            .then(function(data) {
                if (data.success) {
                    emailResults = data.results;
                    var r = data.results;
                    var html = "<table style='margin-top:15px;'>";
                    html += "<tr><td>Dominio</td><td><strong>" + r.domain + "</strong></td></tr>";
                    html += "<tr><td>MX Record</td><td class='" + (r.mx_valid ? "ok" : "error") + "'>" + (r.mx_valid ? "✅ Configurato" : "❌ Non valido") + "</td></tr>";
                    html += "<tr><td>SPF</td><td class='" + (r.spf_valid ? "ok" : "error") + "'>" + (r.spf_valid ? "✅ Protetto" : "❌ Vulnerabile") + "</td></tr>";
                    html += "<tr><td>DMARC</td><td class='" + (r.dmarc_valid ? "ok" : "error") + "'>" + (r.dmarc_valid ? "✅ " + r.dmarc_policy : "❌ Assente") + "</td></tr>";
                    html += "<tr><td>DKIM</td><td class='" + (r.dkim_verified ? "ok" : "error") + "'>" + (r.dkim_verified ? "✅ Verificata" : "❌ Non trovata") + "</td></tr>";
                    html += "<tr><td>TLS</td><td class='" + (r.tls_supported ? "ok" : "error") + "'>" + (r.tls_supported ? "✅ Supportata" : "❌ Non supportata") + "</td></tr>";
                    html += "<tr><td><strong>Punteggio</strong></td><td><strong>" + r.score + "/" + r.max_score + " - " + r.level + "</strong></td></tr>";
                    html += "</table>";
                    document.getElementById("dns-result").innerHTML = html;
                    dnsVerified = true;
                    checkBothTests();
                }
                btn.disabled = false; btn.textContent = "Esegui Test Tecnici";
            });
        }

        function sendOTP() {
            var email = document.getElementById("email").value.trim();
            if (!email) { alert("Inserisci prima l'email aziendale"); return; }
            var btn = document.getElementById("btn-otp-send");
            btn.disabled = true; btn.textContent = "Invio in corso...";
            fetch("/api/send-otp", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({email: email})
            })
            .then(function(resp) { return resp.json(); })
            .then(function(data) {
                if (data.success) {
                    document.getElementById("otp-section").classList.remove("hidden");
                    document.getElementById("otp-result").innerHTML = 
                        "<p class='ok'>✅ Codice OTP: <strong>" + data.code + "</strong></p>" +
                        "<p style='font-size:12px;color:#718096;'>Inserisci questo codice nel campo sopra.</p>";
                } else {
                    document.getElementById("otp-result").innerHTML = "<p class='error'>Errore: " + data.message + "</p>";
                }
                btn.disabled = false; btn.textContent = "Ricevi Codice di Verifica";
            });
        }

        function verifyOTP() {
            var email = document.getElementById("email").value.trim();
            var code = document.getElementById("otp-code").value.trim();
            if (!code) { alert("Inserisci il codice ricevuto"); return; }
            fetch("/api/verify-otp", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({email: email, code: code})
            })
            .then(function(resp) { return resp.json(); })
            .then(function(data) {
                if (data.verified) {
                    otpVerified = true;
                    document.getElementById("otp-result").innerHTML = "<span class='verified-badge'>✅ Identità Confermata</span>";
                    document.getElementById("otp-section").classList.add("hidden");
                    checkBothTests();
                } else {
                    document.getElementById("otp-result").innerHTML = "<p class='error'>❌ Codice errato.</p>";
                }
            });
        }

        function goToStep3() {
            if (!dnsVerified || !otpVerified) { alert("Completa entrambe le verifiche prima di proseguire"); return; }
            document.getElementById("step2").classList.add("hidden");
            document.getElementById("step3").classList.remove("hidden");
            document.getElementById("step3-indicator").classList.add("active");
            document.getElementById("step2-indicator").classList.add("completed");
        }

        function startFullScan() {
            var questions = {};
            for (var i = 1; i <= 10; i++) {
                var s = document.querySelector("input[name='q" + i + "']:checked");
                if (!s) { alert("Rispondi a tutte le domande (manca n." + i + ")"); return; }
                questions["q" + i] = s.value;
            }
            // Determina il target per gli scan in base al tipo di rete
            var scanTarget = document.getElementById("domain").value.trim();
            if (isCorporateNetwork) {
                scanTarget = document.getElementById("public-ip").value.trim() || scanTarget;
            }
            
            var payload = {
                vat_number: document.getElementById("vat").value.trim(),
                domain: document.getElementById("domain").value.trim(),
                public_ip: document.getElementById("public-ip").value.trim(),
                is_corporate_network: isCorporateNetwork,
                ateco: document.getElementById("ateco").value,
                employees: document.getElementById("employees").value,
                email: document.getElementById("email").value.trim(),
                dns_verified: dnsVerified,
                otp_verified: otpVerified,
                email_results: emailResults,
                questions: questions
            };
            document.getElementById("step3").classList.add("hidden");
            var loadingEl = document.getElementById("loading");
            if (loadingEl) loadingEl.style.display = "block";
            fetch("/api/scan", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(payload)
            })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (loadingEl) loadingEl.style.display = "none";
                document.getElementById("step4-indicator").classList.add("active");
                document.getElementById("step3-indicator").classList.add("completed");
                displayResults(d);
            })
            .catch(function() {
                if (loadingEl) loadingEl.style.display = "none";
                document.getElementById("results").innerHTML = "<p class='error'>Errore durante la scansione</p>";
            });
        }

        function displayResults(data) {
            var score = data.score;
            var rc = score.risk_color === "ok" ? "green" : score.risk_color === "warning" ? "yellow" : "red";
            var h = "<div class='card' style='text-align:center;'><h2>Report Quick Scan NIS2</h2>";
            h += "<div class='score-circle score-" + rc + "'>" + score.total_score + "/100</div>";
            h += "<p class='" + score.risk_color + "'><strong>Rischio: " + score.overall_risk + "</strong></p>";
            // Mostra il tipo di rete rilevata
            h += "<p style='font-size:13px;color:#a0aec0;'>Rete: " + (isCorporateNetwork ? "🏢 Aziendale" : "🏠 Domestica/Pubblica") + " | IP: " + detectedIP + "</p>";
            h += "</div>";
            
            h += "<div class='card'><h3>Dati Aziendali</h3><table>";
            h += "<tr><td>Azienda</td><td>" + data.company.name + "</td></tr>";
            h += "<tr><td>Settore</td><td>" + data.company.ateco + "</td></tr>";
            h += "<tr><td>Dipendenti</td><td>" + data.company.employees + "</td></tr>";
            h += "<tr><td>CISO (da questionario)</td><td>" + (data.company.ciso || "N/D") + "</td></tr>";
            var n = score.nis2_category;
            var bc = "badge-blue"; if (n.category === "Essenziale") bc = "badge-red"; else if (n.category === "Importante") bc = "badge-yellow";
            h += "<tr><td>Categoria NIS2</td><td><span class='badge " + bc + "'>" + n.category + "</span></td></tr></table></div>";
            
            h += "<div class='card'><h3>Verifica Email</h3><p>DNS: " + (data.company.dns_verified ? "<span class='ok'>✅ Superato</span>" : "<span class='error'>❌ Non superato</span>") + "</p><p>OTP: " + (data.company.otp_verified ? "<span class='ok'>✅ Superato</span>" : "<span class='error'>❌ Non superato</span>") + "</p></div>";
            
            h += "<div class='card'><h3>Scan Tecnici</h3><table><tr><th>Test</th><th>Punteggio</th><th>Note</th></tr>";
            for (var i = 0; i < score.details.length; i++) {
                var d = score.details[i];
                var cl = d.score === d.max ? "ok" : d.score === 0 ? "error" : "warning";
                h += "<tr><td>" + d.area + "</td><td class='" + cl + "'>" + d.score + "/" + d.max + "</td><td>" + d.note + "</td></tr>";
            }
            h += "</table></div>";
            
            if (score.infra_details && score.infra_details.length > 0) {
                h += "<div class='card'><h3>Infrastruttura e Rete</h3>";
                if (!isCorporateNetwork) {
                    h += "<p style='color:#f6e05e; font-size:13px; margin-bottom:10px;'>⚠️ Test eseguiti in modalità ridotta (rete domestica). Per un assessment completo, esegui il test dalla rete aziendale.</p>";
                }
                h += "<table><tr><th>Test</th><th>Punteggio</th><th>Note</th></tr>";
                for (var j = 0; j < score.infra_details.length; j++) {
                    var d2 = score.infra_details[j];
                    var cl2 = d2.score === d2.max ? "ok" : d2.score === 0 ? "error" : "warning";
                    h += "<tr><td>" + d2.area + "</td><td class='" + cl2 + "'>" + d2.score + "/" + d2.max + "</td><td>" + d2.note + "</td></tr>";
                }
                h += "</table></div>";
            }
            
            h += "<div class='card'><h3>Questionario</h3><table><tr><th>Domanda</th><th>Risposta</th></tr>";
            for (var k = 0; k < score.questionnaire_details.length; k++) {
                var q = score.questionnaire_details[k];
                var ac = q.answer === "si" ? "ok" : "error";
                var at = q.answer === "si" ? "Si" : q.answer === "no" ? "No" : q.answer;
                h += "<tr><td>" + q.question + "</td><td class='" + ac + "'>" + at + "</td></tr>";
            }
            h += "</table></div>";
            
            if (score.recommendations.length > 0) {
                h += "<div class='card'><h3>Azioni Prioritarie</h3><ul>";
                for (var m = 0; m < score.recommendations.length; m++) { h += "<li>" + score.recommendations[m] + "</li>"; }
                h += "</ul></div>";
            }
            
            h += "<div class='cta'><h3>Vuoi un assessment NIS2 completo?</h3><p>Questo Quick Scan ha analizzato la superficie pubblica. Per una verifica approfondita dell'infrastruttura interna, prenota una consulenza gratuita.</p></div>";
            document.getElementById("results").innerHTML = h;
            document.getElementById("results").scrollIntoView({behavior: "smooth"});
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/verify-dns', methods=['POST'])
def verify_dns():
    email = request.json.get('email', '')
    domain = email.split('@')[-1] if '@' in email else ''
    results = {"email": email, "domain": domain, "mx_valid": False, "spf_valid": False, "spf_record": "", "dmarc_valid": False, "dmarc_policy": "", "dkim_verified": False, "tls_supported": False, "score": 0, "max_score": 25}
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        if mx: results["mx_valid"] = True; results["score"] += 5
    except: pass
    try:
        for rdata in dns.resolver.resolve(domain, 'TXT'):
            t = str(rdata)
            if "v=spf1" in t: results["spf_valid"] = True; results["spf_record"] = t[:200]; results["score"] += 5; break
    except: pass
    try:
        for rdata in dns.resolver.resolve(f"_dmarc.{domain}", 'TXT'):
            t = str(rdata)
            if "v=DMARC1" in t:
                results["dmarc_valid"] = True; results["score"] += 5
                if "p=reject" in t: results["dmarc_policy"] = "reject"; results["score"] += 3
                elif "p=quarantine" in t: results["dmarc_policy"] = "quarantine"; results["score"] += 2
                else: results["dmarc_policy"] = "none"
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
    if results["mx_valid"]:
        try:
            mx_host = str(dns.resolver.resolve(domain, 'MX')[0].exchange)
            with smtplib.SMTP(mx_host, 25, timeout=5) as s: s.starttls(); results["tls_supported"] = True; results["score"] += 2
        except: pass
    if results["score"] >= 20: results["level"] = "CONFORME"
    elif results["score"] >= 12: results["level"] = "PARZIALE"
    else: results["level"] = "NON CONFORME"
    return jsonify({"success": True, "results": results})

@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    email = request.json.get('email', '')
    code = ''.join(random.choices(string.digits, k=6))
    verification_codes[email] = code
    print(f"CODICE OTP per {email}: {code}")
    return jsonify({"success": True, "message": "Codice generato", "code": code})

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    email = request.json.get('email', '')
    code = request.json.get('code', '')
    expected = verification_codes.get(email, '')
    verified = (expected == code)
    if verified:
        del verification_codes[email]
    return jsonify({"verified": verified})

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    company_data = lookup_company(data.get('vat_number', ''))
    if company_data is None:
        company_data = {"name": "Partita IVA non trovata", "ateco": data.get('ateco','N/D'), "employees": data.get('employees','N/D'), "address": "N/D", "legal_form": "N/D", "status": "error"}
    else:
        company_data["ateco"] = data.get('ateco','N/D')
        company_data["employees"] = data.get('employees','N/D')
    
    # Il CISO ora arriva dal questionario (domanda q3)
    questions = data.get('questions', {})
    ciso_answer = questions.get('q3', 'no')
    if ciso_answer == 'si_interno':
        company_data["ciso"] = "Interno"
    elif ciso_answer == 'si_esterno':
        company_data["ciso"] = "Consulente esterno"
    else:
        company_data["ciso"] = "Assente"
    
    company_data["email"] = data.get('email','')
    company_data["dns_verified"] = data.get('dns_verified', False)
    company_data["otp_verified"] = data.get('otp_verified', False)
    company_data["vat"] = data.get('vat_number','')
    company_data["is_corporate_network"] = data.get('is_corporate_network', False)
    
    # Target per gli scan: in base al tipo di rete
    is_corporate = data.get('is_corporate_network', False)
    if is_corporate:
        target = data.get('public_ip', '') or data.get('domain', '')
    else:
        target = data.get('domain', '')
    
    scan_results = scan_domain(target)
    score = calculate_nis2_score(company_data, scan_results, questions)
    
    return jsonify({"company": company_data, "domain": data.get('domain',''), "scan": scan_results, "score": score})

if __name__ == '__main__':
    app.run(debug=True)