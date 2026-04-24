# Mappatura settori NIS2 basata su codici ATECO
NIS2_SECTORS = {
    "energia": {
        "ateco_prefix": ["05", "06", "07", "08", "09", "19", "35"],
        "category": "Essenziale",
        "description": "Energia (elettrica, gas, petrolio)"
    },
    "trasporti": {
        "ateco_prefix": ["49", "50", "51", "52", "53"],
        "category": "Essenziale",
        "description": "Trasporti (aereo, ferroviario, marittimo, stradale)"
    },
    "sanita": {
        "ateco_prefix": ["86", "87", "88"],
        "category": "Essenziale",
        "description": "Sanità e assistenza"
    },
    "acqua": {
        "ateco_prefix": ["36", "37", "38", "39"],
        "category": "Essenziale",
        "description": "Acqua potabile e acque reflue"
    },
    "digitale": {
        "ateco_prefix": ["61", "62", "63", "58", "59", "60"],
        "category": "Importante",
        "description": "Infrastrutture digitali e servizi ICT"
    },
    "finanza": {
        "ateco_prefix": ["64", "65", "66"],
        "category": "Importante",
        "description": "Servizi finanziari e bancari"
    },
    "pubblica": {
        "ateco_prefix": ["84"],
        "category": "Essenziale",
        "description": "Pubblica Amministrazione"
    },
    "manifatturiero": {
        "ateco_prefix": ["10", "11", "13", "14", "20", "21", "24", "25", "26", "27", "28", "29", "30"],
        "category": "Importante",
        "description": "Manifatturiero critico"
    },
    "chimico": {
        "ateco_prefix": ["20", "21", "22"],
        "category": "Essenziale",
        "description": "Sostanze chimiche"
    },
    "postale": {
        "ateco_prefix": ["53.2", "53.20"],
        "category": "Essenziale",
        "description": "Servizi postali e corrieri"
    }
}

def get_nis2_category(ateco_code, employees_str):
    """
    Determina la categoria NIS2 in base a ATECO e dipendenti.
    Restituisce: 'Essenziale', 'Importante', 'Altro'
    """
    if not ateco_code or ateco_code == "N/D":
        return {"category": "N/D", "description": "Impossibile determinare senza ATECO"}
    
    category = "Altro"
    description = "Settore non classificato come essenziale/importante"
    
    for sector, info in NIS2_SECTORS.items():
        for prefix in info["ateco_prefix"]:
            if ateco_code.startswith(prefix):
                category = info["category"]
                description = info["description"]
                break
        if category != "Altro":
            break
    
    # Aggiusta in base ai dipendenti (soglia 50 per importanti, 250 per essenziali)
    try:
        employees = int(''.join(filter(str.isdigit, str(employees_str))))
        if category == "Importante" and employees >= 250:
            category = "Essenziale"
        elif category == "Altro" and employees >= 50:
            category = "Importante"
            description = "PMI in settore non critico ma con numero significativo di dipendenti"
    except:
        pass
    
    return {"category": category, "description": description}

def calculate_nis2_score(company_data, scan_results, questions=None):
    """
    Calcola il punteggio NIS2 completo (tecnico + questionario + email + CISO).
    """
    technical_score = 0
    details = []
    recommendations = []
    
    # === PUNTEGGIO TECNICO (max 40 punti) ===
    
    # SSL (8 punti)
    ssl = scan_results.get("ssl", {})
    if ssl.get("valid"):
        days = ssl.get("days_left", 0)
        if days > 90:
            technical_score += 8
            details.append({"area": "SSL", "score": 8, "max": 8, "note": f"Valido ({days} giorni)"})
        elif days > 30:
            technical_score += 5
            details.append({"area": "SSL", "score": 5, "max": 8, "note": f"In scadenza tra {days} giorni"})
        else:
            technical_score += 2
            details.append({"area": "SSL", "score": 2, "max": 8, "note": f"Scadenza imminente ({days} giorni)"})
    else:
        details.append({"area": "SSL", "score": 0, "max": 8, "note": "Non valido"})
        recommendations.append("Installare certificato SSL valido")
    
    # Header sicurezza (10 punti)
    headers = scan_results.get("headers", {})
    if headers:
        present = sum(1 for h in headers.values() if h.get("status") == "presente")
        total = len(headers)
        score = int((present / total) * 10)
        technical_score += score
        details.append({"area": "Header Sicurezza", "score": score, "max": 10, "note": f"{present}/{total} presenti"})
        if present < 4:
            recommendations.append("Configurare header di sicurezza HTTP mancanti")
    
    # DMARC (8 punti)
    dmarc = scan_results.get("dmarc", {})
    if dmarc.get("presente"):
        policy = dmarc.get("policy", "none")
        if policy == "reject":
            technical_score += 8
            details.append({"area": "DMARC", "score": 8, "max": 8, "note": "Policy reject"})
        elif policy == "quarantine":
            technical_score += 5
            details.append({"area": "DMARC", "score": 5, "max": 8, "note": "Policy quarantine"})
        else:
            technical_score += 3
            details.append({"area": "DMARC", "score": 3, "max": 8, "note": "Policy none (debole)"})
    else:
        details.append({"area": "DMARC", "score": 0, "max": 8, "note": "Assente"})
        recommendations.append("Implementare DMARC per anti-spoofing")
    
    # SPF (4 punti)
    spf = scan_results.get("spf", {})
    if spf.get("presente"):
        technical_score += 4
        details.append({"area": "SPF", "score": 4, "max": 4, "note": "Presente"})
    else:
        details.append({"area": "SPF", "score": 0, "max": 4, "note": "Assente"})
        recommendations.append("Configurare record SPF")
    
    # Data Breach (5 punti)
    breach = scan_results.get("breach", {})
    if not breach.get("found"):
        technical_score += 5
        details.append({"area": "Data Breach", "score": 5, "max": 5, "note": "Nessuno trovato"})
    else:
        details.append({"area": "Data Breach", "score": 0, "max": 5, "note": f"Trovati {breach.get('count', 0)} breach"})
        recommendations.append("Investigare data breach rilevati")
    
    # DNSSEC (5 punti)
    dnssec = scan_results.get("dnssec", {})
    if dnssec.get("enabled"):
        technical_score += 5
        details.append({"area": "DNSSEC", "score": 5, "max": 5, "note": "Abilitato"})
    else:
        details.append({"area": "DNSSEC", "score": 0, "max": 5, "note": "Non abilitato"})
    
    # === PUNTEGGIO QUESTIONARIO (max 30 punti, 5 punti per domanda) ===
    questionnaire_score = 0
    questionnaire_details = []
    
    question_map = {
        "q1": "Politica di sicurezza documentata",
        "q2": "Piano di risposta incidenti",
        "q3": "Backup regolari verificati",
        "q4": "MFA per accessi critici",
        "q5": "Gestione aggiornamenti e vulnerabilità",
        "q6": "Verifica sicurezza fornitori"
    }
    
    if questions:
        for key, label in question_map.items():
            answer = questions.get(key, "no")
            if answer == "si":
                questionnaire_score += 5
                questionnaire_details.append({"question": label, "answer": "si"})
            else:
                questionnaire_details.append({"question": label, "answer": "no"})
                if key == "q1":
                    recommendations.append("Redigere una politica di sicurezza formalizzata")
                elif key == "q2":
                    recommendations.append("Creare un piano di risposta agli incidenti")
                elif key == "q3":
                    recommendations.append("Implementare backup regolari e test di ripristino")
                elif key == "q4":
                    recommendations.append("Attivare MFA per tutti gli accessi critici")
                elif key == "q5":
                    recommendations.append("Stabilire un processo di gestione aggiornamenti")
                elif key == "q6":
                    recommendations.append("Avviare verifica sicurezza dei fornitori")
        
        # Certificazioni (bonus, non obbligatorio)
        q7 = questions.get("q7", "no")
        if q7 != "no":
            questionnaire_score += 3
            questionnaire_details.append({"question": "Certificazioni di sicurezza", "answer": q7})
        else:
            questionnaire_details.append({"question": "Certificazioni di sicurezza", "answer": "no"})
    
    # === PUNTEGGIO CISO (max 10 punti) ===
    ciso = company_data.get("ciso", "Assente")
    ciso_score = 0
    if ciso == "Interno":
        ciso_score = 10
    elif ciso == "Consulente esterno":
        ciso_score = 6
    else:
        ciso_score = 0
        recommendations.append("Nominare un CISO o referente sicurezza")
    
    # === PUNTEGGIO EMAIL VERIFICATA (max 5 punti) ===
    email_score = 5 if company_data.get("email_verified", False) else 0
    if not company_data.get("email_verified", False):
        recommendations.append("Completare verifica email aziendale")
    
    # === PUNTEGGIO TOTALE ===
    total_score = technical_score + questionnaire_score + ciso_score + email_score
    total_score = min(total_score, 100)
    
    # === CATEGORIA NIS2 ===
    nis2_info = get_nis2_category(company_data.get("ateco", ""), company_data.get("employees", ""))
    
    # === RISCHIO COMPLESSIVO ===
    if nis2_info["category"] == "Essenziale" and total_score < 50:
        overall_risk = "CRITICO"
        risk_color = "error"
    elif nis2_info["category"] == "Essenziale" and total_score < 75:
        overall_risk = "ALTO"
        risk_color = "warning"
    elif nis2_info["category"] == "Importante" and total_score < 40:
        overall_risk = "CRITICO"
        risk_color = "error"
    elif nis2_info["category"] == "Importante" and total_score < 60:
        overall_risk = "ALTO"
        risk_color = "warning"
    elif total_score >= 80:
        overall_risk = "BASSO"
        risk_color = "ok"
    elif total_score >= 50:
        overall_risk = "MEDIO"
        risk_color = "warning"
    else:
        overall_risk = "CRITICO"
        risk_color = "error"
    
    # === CERTIFICAZIONI EQUIVALENTI ===
    cert_status = check_certification_equivalence(scan_results, company_data)
    
    return {
        "total_score": total_score,
        "technical_score": technical_score,
        "questionnaire_score": questionnaire_score,
        "ciso_score": ciso_score,
        "email_score": email_score,
        "nis2_category": nis2_info,
        "overall_risk": overall_risk,
        "risk_color": risk_color,
        "details": details,
        "questionnaire_details": questionnaire_details,
        "recommendations": recommendations,
        "certifications": cert_status
    }
def check_certification_equivalence(scan_results, company_data):
    """
    Verifica se la configurazione attuale e' equivalente a certificazioni note.
    """
    cert_status = []
    
    ssl = scan_results.get("ssl", {})
    headers = scan_results.get("headers", {})
    dmarc = scan_results.get("dmarc", {})
    spf = scan_results.get("spf", {})
    dnssec = scan_results.get("dnssec", {})
    
    headers_ok = sum(1 for h in headers.values() if h.get("status") == "presente")
    
    # ISO 27001 equivalente?
    iso_score = 0
    if ssl.get("valid"):
        iso_score += 20
    if headers_ok >= 5:
        iso_score += 30
    if dmarc.get("policy") in ["reject", "quarantine"]:
        iso_score += 25
    if spf.get("presente"):
        iso_score += 15
    if dnssec.get("enabled"):
        iso_score += 10
    
    if iso_score >= 80:
        cert_status.append({"certification": "ISO 27001", "readiness": "Alta", 
                           "note": "Configurazione coerente con requisiti ISO 27001"})
    elif iso_score >= 50:
        cert_status.append({"certification": "ISO 27001", "readiness": "Media", 
                           "note": "Buone basi ma servono miglioramenti per ISO 27001"})
    else:
        cert_status.append({"certification": "ISO 27001", "readiness": "Bassa", 
                           "note": "Lontano dai requisiti minimi ISO 27001"})
    
    return cert_status