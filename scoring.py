# Mappatura settori NIS2 basata su codici ATECO
NIS2_SECTORS = {
    "energia": {"ateco_prefix": ["05", "06", "07", "08", "09", "19", "35"], "category": "Essenziale", "description": "Energia (elettrica, gas, petrolio)"},
    "trasporti": {"ateco_prefix": ["49", "50", "51", "52", "53"], "category": "Essenziale", "description": "Trasporti (aereo, ferroviario, marittimo, stradale)"},
    "sanita": {"ateco_prefix": ["86", "87", "88"], "category": "Essenziale", "description": "Sanità e assistenza"},
    "acqua": {"ateco_prefix": ["36", "37", "38", "39"], "category": "Essenziale", "description": "Acqua potabile e acque reflue"},
    "digitale": {"ateco_prefix": ["61", "62", "63", "58", "59", "60"], "category": "Importante", "description": "Infrastrutture digitali e servizi ICT"},
    "finanza": {"ateco_prefix": ["64", "65", "66"], "category": "Importante", "description": "Servizi finanziari e bancari"},
    "pubblica": {"ateco_prefix": ["84"], "category": "Essenziale", "description": "Pubblica Amministrazione"},
    "manifatturiero": {"ateco_prefix": ["10", "11", "13", "14", "20", "21", "24", "25", "26", "27", "28", "29", "30"], "category": "Importante", "description": "Manifatturiero critico"},
    "chimico": {"ateco_prefix": ["20", "21", "22"], "category": "Essenziale", "description": "Sostanze chimiche"},
    "postale": {"ateco_prefix": ["53.2", "53.20"], "category": "Essenziale", "description": "Servizi postali e corrieri"}
}


def get_nis2_category(ateco_code, employees_str):
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


def check_certification_equivalence(scan_results, company_data):
    cert_status = []
    ssl = scan_results.get("ssl", {})
    headers = scan_results.get("headers", {})
    dmarc = scan_results.get("dmarc", {})
    spf = scan_results.get("spf", {})
    dnssec = scan_results.get("dnssec", {})
    headers_ok = sum(1 for h in headers.values() if h.get("status") == "presente")
    iso_score = 0
    if ssl.get("valid"): iso_score += 20
    if headers_ok >= 5: iso_score += 30
    if dmarc.get("policy") in ["reject", "quarantine"]: iso_score += 25
    if spf.get("presente"): iso_score += 15
    if dnssec.get("enabled"): iso_score += 10
    if iso_score >= 80:
        cert_status.append({"certification": "ISO 27001", "readiness": "Alta", "note": "Configurazione coerente con requisiti ISO 27001"})
    elif iso_score >= 50:
        cert_status.append({"certification": "ISO 27001", "readiness": "Media", "note": "Buone basi ma servono miglioramenti"})
    else:
        cert_status.append({"certification": "ISO 27001", "readiness": "Bassa", "note": "Lontano dai requisiti minimi"})
    return cert_status


def calculate_nis2_score(company_data, scan_results, questions=None):
    technical_score = 0
    details = []
    recommendations = []

    # ============================================================
    # SITO WEB (max 35 punti)
    # ============================================================

    ssl = scan_results.get("ssl", {})
    if ssl.get("valid"):
        days = ssl.get("days_left", 0)
        if days > 90:
            technical_score += 10
            details.append({"area": "SSL (Art. 21.2.h)", "score": 10, "max": 10, "note": f"Valido ({days} giorni)"})
        elif days > 30:
            technical_score += 6
            details.append({"area": "SSL (Art. 21.2.h)", "score": 6, "max": 10, "note": f"In scadenza tra {days} giorni"})
        else:
            technical_score += 3
            details.append({"area": "SSL (Art. 21.2.h)", "score": 3, "max": 10, "note": f"Scadenza imminente ({days} giorni)"})
    else:
        details.append({"area": "SSL (Art. 21.2.h)", "score": 0, "max": 10, "note": "Non valido o assente"})
        recommendations.append("Installare un certificato SSL valido (Art. 21.2.h)")

    headers = scan_results.get("headers", {})
    if headers:
        present = sum(1 for h in headers.values() if h.get("status") == "presente")
        total = len(headers)
        score = int((present / total) * 15)
        technical_score += score
        details.append({"area": "Header Sicurezza (Art. 21.2.a)", "score": score, "max": 15, "note": f"{present}/{total} header presenti"})
        if present < 4:
            recommendations.append("Configurare gli header di sicurezza HTTP mancanti (Art. 21.2.a)")

    cms = scan_results.get("cms", {})
    risks = cms.get("risks", [])
    if len(risks) == 0:
        technical_score += 5
        details.append({"area": "CMS e Tecnologie (Art. 21.2.e)", "score": 5, "max": 5, "note": "Nessuna vulnerabilità rilevata"})
    elif len(risks) <= 2:
        technical_score += 2
        details.append({"area": "CMS e Tecnologie (Art. 21.2.e)", "score": 2, "max": 5, "note": f"{len(risks)} rischi rilevati"})
    else:
        details.append({"area": "CMS e Tecnologie (Art. 21.2.e)", "score": 0, "max": 5, "note": f"{len(risks)} rischi critici!"})

    waf = scan_results.get("waf", {})
    if waf.get("protected"):
        technical_score += 5
        details.append({"area": "WAF (Art. 21.2.a)", "score": 5, "max": 5, "note": "Protetto"})
    else:
        details.append({"area": "WAF (Art. 21.2.a)", "score": 0, "max": 5, "note": "Nessun WAF rilevato"})

    # ============================================================
    # EMAIL (max 15 punti)
    # ============================================================
    dmarc = scan_results.get("dmarc", {})
    if dmarc.get("presente"):
        policy = dmarc.get("policy", "none")
        if policy == "reject":
            technical_score += 8
            details.append({"area": "DMARC (Art. 21.2.a)", "score": 8, "max": 8, "note": "Policy reject"})
        elif policy == "quarantine":
            technical_score += 5
            details.append({"area": "DMARC (Art. 21.2.a)", "score": 5, "max": 8, "note": "Policy quarantine"})
        else:
            technical_score += 3
            details.append({"area": "DMARC (Art. 21.2.a)", "score": 3, "max": 8, "note": "Policy none (debole)"})
    else:
        details.append({"area": "DMARC (Art. 21.2.a)", "score": 0, "max": 8, "note": "Assente"})

    spf = scan_results.get("spf", {})
    if spf.get("presente"):
        technical_score += 4
        details.append({"area": "SPF (Art. 21.2.a)", "score": 4, "max": 4, "note": "Configurato"})
    else:
        details.append({"area": "SPF (Art. 21.2.a)", "score": 0, "max": 4, "note": "Assente"})

    dnssec = scan_results.get("dnssec", {})
    if dnssec.get("enabled"):
        technical_score += 3
        details.append({"area": "DNSSEC (Art. 21.2.a)", "score": 3, "max": 3, "note": "Abilitato"})
    else:
        details.append({"area": "DNSSEC (Art. 21.2.a)", "score": 0, "max": 3, "note": "Non abilitato"})

    # ============================================================
    # QUESTIONARIO (max 30 punti)
    # ============================================================
    questionnaire_score = 0
    questionnaire_details = []

    question_map = {
        "q1": {"label": "Registrazione al portale ACN", "art": "Art. 7 D.Lgs. 138/2024"},
        "q2": {"label": "Designazione Punto di Contatto", "art": "Art. 7 D.Lgs. 138/2024"},
        "q3": {"label": "CISO o referente sicurezza", "art": "Art. 20 D.Lgs. 138/2024"},
        "q4": {"label": "Analisi dei rischi documentata", "art": "Art. 21.2.a"},
        "q5": {"label": "Gestione e notifica incidenti", "art": "Art. 21.2.b"},
        "q6": {"label": "Politiche di sicurezza e accessi (MFA, backup, cifratura)", "art": "Art. 21.2.i, h"},
        "q7": {"label": "Patch management e gestione vulnerabilità", "art": "Art. 21.2.e"},
        "q8": {"label": "Verifica sicurezza fornitori", "art": "Art. 21.2.d"},
        "q9": {"label": "Formazione cybersicurezza", "art": "Art. 20 D.Lgs. 138/2024"},
        "q10": {"label": "Certificazioni di sicurezza", "art": "ISO 27001 / Linee guida ACN"}
    }

    if questions:
        for key, info in question_map.items():
            answer = questions.get(key, "no")
            if answer in ["si", "si_interno", "si_esterno"]:
                questionnaire_score += 3
                questionnaire_details.append({"question": f"{info['label']} ({info['art']})", "answer": "si"})
            elif answer in ["parziale", "saltuaria", "in_corso"]:
                questionnaire_score += 1.5
                questionnaire_details.append({"question": f"{info['label']} ({info['art']})", "answer": "parziale"})
            else:
                questionnaire_details.append({"question": f"{info['label']} ({info['art']})", "answer": "no"})

    # ============================================================
    # CISO (max 5 punti)
    # ============================================================
    ciso = company_data.get("ciso", "Assente")
    ciso_score = 5 if ciso == "Interno" else 3 if ciso == "Consulente esterno" else 0

    # ============================================================
    # VERIFICA EMAIL (max 10 punti)
    # ============================================================
    email_score = 0
    if company_data.get("dns_verified"): email_score += 5
    if company_data.get("otp_verified"): email_score += 5

    # ============================================================
    # PUNTEGGIO TOTALE
    # ============================================================
    total_score = technical_score + questionnaire_score + ciso_score + email_score
    total_score = min(total_score, 100)

    nis2_info = get_nis2_category(company_data.get("ateco", ""), company_data.get("employees", ""))

    if nis2_info["category"] == "Essenziale" and total_score < 50:
        overall_risk, risk_color = "CRITICO", "error"
    elif nis2_info["category"] == "Essenziale" and total_score < 75:
        overall_risk, risk_color = "ALTO", "warning"
    elif nis2_info["category"] == "Importante" and total_score < 40:
        overall_risk, risk_color = "CRITICO", "error"
    elif nis2_info["category"] == "Importante" and total_score < 60:
        overall_risk, risk_color = "ALTO", "warning"
    elif total_score >= 80:
        overall_risk, risk_color = "BASSO", "ok"
    elif total_score >= 50:
        overall_risk, risk_color = "MEDIO", "warning"
    else:
        overall_risk, risk_color = "CRITICO", "error"

    cert_status = check_certification_equivalence(scan_results, company_data)

    return {
        "total_score": total_score,
        "nis2_category": nis2_info,
        "overall_risk": overall_risk,
        "risk_color": risk_color,
        "details": details,
        "questionnaire_details": questionnaire_details,
        "recommendations": recommendations,
        "certifications": cert_status
    }