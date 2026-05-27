# ─────────────────────────────────────────────────────────────────
# NIS2 — Allegato I (Settori Essenziali)  D.Lgs. 138/2024
# ─────────────────────────────────────────────────────────────────
ANNEX_I_PREFIXES = [
    '05','06','07','08','09','19',   # Estrazione/raffinazione energia
    '35',                             # Energia elettrica, gas, vapore
    '36',                             # Acqua potabile
    '37',                             # Acque reflue
    '49','50','51','52',              # Trasporti (terra/mare/aria/logistica)
    '61','62','63',                   # TLC / ICT / Data center
    '64','65','66',                   # Servizi finanziari e bancari
    '84',                             # Pubblica Amministrazione
    '86','87','88',                   # Sanità e assistenza
]

# ─────────────────────────────────────────────────────────────────
# NIS2 — Allegato II (Settori Importanti)
# ─────────────────────────────────────────────────────────────────
ANNEX_II_PREFIXES = [
    '10','11',                        # Alimentare e bevande
    '13','14',                        # Tessile/abbigliamento
    '20','21','22',                   # Chimico, farmaceutico, plastica
    '24','25','26','27','28','29','30',# Manifatturiero critico
    '38','39',                        # Gestione rifiuti
    '53',                             # Postale e corrieri
    '58','59','60',                   # Media e editoria digitale
    '72','73',                        # Ricerca scientifica e tecnica
]

# ─────────────────────────────────────────────────────────────────
# Domande differenziate per categoria NIS2
# ─────────────────────────────────────────────────────────────────
QUESTION_MAP_BY_CATEGORY = {
    "Essenziale": {
        "q1":  {"label": "Registrazione ACN + Punto di Contatto formale designato",
                "art": "Art. 7 D.Lgs. 138/2024",
                "weight": "CRITICO",
                "consequence": "Obbligo legale — sanzioni fino a 10M€ o 2% fatturato",
                "portable": "Checklist obblighi ACN, scadenzario registrazione, gestione documentale"},
        "q2":  {"label": "CISO designato formalmente con mandato scritto e budget dedicato",
                "art": "Art. 20 D.Lgs. 138/2024",
                "weight": "CRITICO",
                "consequence": "Responsabilità penale per gli organi direttivi in caso di incidente",
                "portable": "Modulo CISO virtuale: roadmap, KPI sicurezza, reportistica CdA"},
        "q3":  {"label": "Analisi dei rischi documentata, aggiornata almeno annualmente",
                "art": "Art. 21.2.a",
                "weight": "CRITICO",
                "consequence": "Impossibile dimostrare conformità in audit — sanzione certa",
                "portable": "Analisi rischi guidata (asset, minacce, impatto) con report PDF NIS2"},
        "q4":  {"label": "Piano notifica incidenti ad ACN entro 24h (primo report) e 72h (dettaglio)",
                "art": "Art. 24 D.Lgs. 138/2024",
                "weight": "CRITICO",
                "consequence": "Mancata notifica = sanzione automatica, obbligo non derogabile",
                "portable": "Workflow notifica incidenti, template per ACN, log eventi sicurezza"},
        "q5":  {"label": "Business Continuity Plan (BCP) formale e testato con esercitazioni",
                "art": "Art. 21.2.c",
                "weight": "ALTO",
                "consequence": "Interruzione prolungata servizi critici senza piano di ripristino",
                "portable": "Template BCP, scenari di crisi, registro test e risultati"},
        "q6":  {"label": "MFA obbligatorio, cifratura endpoint, password policy formale documentata",
                "art": "Art. 21.2.h, i",
                "weight": "ALTO",
                "consequence": "Accesso non autorizzato a sistemi critici con privilegi elevati",
                "portable": "Verifica MFA, policy password, cifratura endpoint e stato backup"},
        "q7":  {"label": "Patch management strutturato con SLA definiti e registro vulnerabilità",
                "art": "Art. 21.2.e",
                "weight": "ALTO",
                "consequence": "Sistemi non patchati = vettore primario attacchi ransomware",
                "portable": "Inventario asset, stato patch OS/software, scansione vulnerabilità"},
        "q8":  {"label": "Audit sicurezza fornitori critici + contratti con clausole security e SLA",
                "art": "Art. 21.2.d",
                "weight": "ALTO",
                "consequence": "Il 62% degli attacchi NIS2 parte dalla supply chain",
                "portable": "Questionario fornitori, scoring supply chain, registro contratti"},
        "q9":  {"label": "Formazione cybersicurezza obbligatoria, documentata e verificata",
                "art": "Art. 20 D.Lgs. 138/2024",
                "weight": "MEDIO",
                "consequence": "Phishing sfrutta la mancanza di formazione — vettore nel 90% degli attacchi",
                "portable": "Moduli formazione NIS2, simulazioni phishing, tracciamento completamento"},
        "q10": {"label": "Penetration test o audit di sicurezza indipendente almeno annuale",
                "art": "Linee Guida ACN",
                "weight": "MEDIO",
                "consequence": "Vulnerabilità non rilevate, difficile dimostrare conformità a clienti e PA",
                "portable": "Roadmap certificazione ISO 27001 con gap analysis e piano implementazione"},
    },
    "Importante": {
        "q1": {"label": "Registrazione al portale ACN e designazione Punto di Contatto",
               "art": "Art. 7 D.Lgs. 138/2024",
               "weight": "CRITICO",
               "consequence": "Obbligo legale — sanzioni fino a 7M€ o 1.4% fatturato",
               "portable": "Checklist obblighi ACN e gestione documentale"},
        "q2": {"label": "Responsabile della sicurezza informatica identificato",
               "art": "Art. 20 D.Lgs. 138/2024",
               "weight": "ALTO",
               "consequence": "Mancanza di governance — responsabilità degli organi direttivi",
               "portable": "Modulo CISO virtuale con supporto alla governance"},
        "q3": {"label": "Analisi dei rischi (anche semplificata) documentata",
               "art": "Art. 21.2.a",
               "weight": "ALTO",
               "consequence": "Impossibilità di dimostrare conformità in caso di audit",
               "portable": "Analisi dei rischi guidata con report PDF NIS2"},
        "q4": {"label": "Processo gestione incidenti con notifica ad ACN entro 72h",
               "art": "Art. 24 D.Lgs. 138/2024",
               "weight": "CRITICO",
               "consequence": "Mancata notifica incidente = sanzione, anche per soggetti Importanti",
               "portable": "Workflow notifica incidenti e template per ACN"},
        "q5": {"label": "MFA attivo, backup verificati e cifratura dati critici",
               "art": "Art. 21.2.h, i",
               "weight": "ALTO",
               "consequence": "Accesso non autorizzato, perdita dati e interruzione servizi",
               "portable": "Verifica MFA, policy accessi, stato backup e cifratura"},
        "q6": {"label": "Verifica sicurezza fornitori e partner critici",
               "art": "Art. 21.2.d",
               "weight": "ALTO",
               "consequence": "Attacchi via supply chain in crescita costante",
               "portable": "Questionario fornitori e scoring sicurezza supply chain"},
        "q7": {"label": "Formazione cybersicurezza per dipendenti e collaboratori",
               "art": "Art. 20 D.Lgs. 138/2024",
               "weight": "MEDIO",
               "consequence": "Phishing rimane il vettore principale degli incidenti",
               "portable": "Moduli formazione e simulazioni phishing"},
    },
    "Fornitore NIS2": {
        "fq1": {"label": "Accessi remoti ai sistemi del cliente: nominativi, MFA obbligatoria, session recording",
                "art": "Art. 21.2.d — Supply Chain Security",
                "weight": "CRITICO",
                "consequence": "Accesso non nominativo o senza MFA = vettore diretto di attacco verso il cliente NIS2",
                "portable": "Verifica MFA deployment, accessi nominativi tracciati, session recording, revoca accessi inattivi"},
        "fq2": {"label": "Account privilegiati separati dagli account standard, accessi temporanei approvati e tracciati (PAM)",
                "art": "Art. 21.2.d — Supply Chain Security",
                "weight": "CRITICO",
                "consequence": "Account condivisi o privilegiati non revocati = responsabilità diretta in caso di incidente al cliente",
                "portable": "PAM check: separazione account admin, least privilege, session recording, log accessi privilegiati"},
        "fq3": {"label": "Incident Response Plan con notifica al cliente entro 24-48h (prima che scatti il suo obbligo ACN)",
                "art": "Art. 21.2.d + Art. 24 D.Lgs. 138/2024",
                "weight": "CRITICO",
                "consequence": "Il cliente NIS2 deve notificare ACN entro 24h — se non riceve la tua notifica prima è inadempiente",
                "portable": "Template IRP fornitore, workflow notifica cliente, escalation automatica, registro incidenti"},
        "fq4": {"label": "BCP/DRP con RTO e RPO definiti e testati per i servizi erogati al cliente",
                "art": "Art. 21.2.d + Art. 21.2.c",
                "weight": "ALTO",
                "consequence": "Se ti fermi si ferma il cliente NIS2 — senza RTO/RPO documentati rischi esclusione dai contratti",
                "portable": "Template BCP fornitore, definizione RTO/RPO per servizio, log test DR periodici"},
        "fq5": {"label": "Vulnerability assessment periodici e patch management con SLA per vulnerabilità critiche",
                "art": "Art. 21.2.d + Art. 21.2.e",
                "weight": "ALTO",
                "consequence": "Vulnerabilità non gestite sul tuo stack = superficie di attacco verso i sistemi del cliente",
                "portable": "Inventario asset, scan VA, SLA patch critiche (<72h), remediation tracking con evidenza"},
        "fq6": {"label": "Clausole contrattuali NIS2: security SLA, audit rights, obblighi notifica incidente",
                "art": "Art. 21.2.d",
                "weight": "ALTO",
                "consequence": "Il cliente è obbligato ad includere clausole di sicurezza — se non le hai rischi rescissione contratto",
                "portable": "Template clausole NIS2, SLA sicurezza, diritti di audit, registro contratti con clienti NIS2"},
        "fq7": {"label": "Onboarding/offboarding: accessi revocati entro 24h dalla cessazione del rapporto operativo",
                "art": "Art. 21.2.d",
                "weight": "MEDIO",
                "consequence": "Account attivi di ex-collaboratori sui sistemi del cliente = rischio accesso non autorizzato",
                "portable": "Processo onboarding/offboarding, revoca accessi automatica, registro utenti attivi per cliente"},
        "fq8": {"label": "Formazione cybersicurezza per il personale con accesso ai sistemi o dati del cliente",
                "art": "Art. 21.2.d",
                "weight": "MEDIO",
                "consequence": "I tuoi tecnici sono il vettore più comune per attacchi phishing verso il cliente NIS2",
                "portable": "Moduli formazione NIS2 per ruolo, simulazioni phishing, tracciamento completamento con attestati"},
    },
    "Fuori ambito": {
        "q1": {"label": "Backup regolari, verificati e conservati off-site",
               "art": "Best practice ENISA",
               "weight": "MEDIO",
               "consequence": "Perdita dati irreversibile in caso di ransomware o guasto",
               "portable": "Verifica stato backup e piano di ripristino"},
        "q2": {"label": "Aggiornamenti software e patch di sicurezza applicati regolarmente",
               "art": "Best practice ENISA",
               "weight": "MEDIO",
               "consequence": "Sistemi non aggiornati = vulnerabilità note sfruttabili facilmente",
               "portable": "Inventario software e stato aggiornamenti"},
        "q3": {"label": "Formazione base sulla cybersicurezza per i dipendenti",
               "art": "Best practice ENISA",
               "weight": "BASSO",
               "consequence": "Phishing e social engineering colpiscono anche le PMI",
               "portable": "Moduli base formazione cybersicurezza"},
    },
}


def _parse_employees(employees_str):
    """Restituisce il numero approssimativo di dipendenti dalla fascia."""
    mapping = {'1-10': 5, '11-50': 30, '51-250': 150, '250+': 300}
    return mapping.get(str(employees_str).strip(), 0)


def _parse_revenue(revenue_str):
    """Restituisce True/False per large e medium basandosi sulla fascia fatturato."""
    rev = str(revenue_str).strip().lower()
    is_large  = rev == 'grande'          # > 50M€
    is_medium = rev == 'media'           # 10–50M€
    return is_large, is_medium


def get_nis2_category(ateco_code, employees_str, revenue_str='', is_supplier=False):
    """
    Classifica l'organizzazione secondo D.Lgs. 138/2024:
    Essenziale / Importante / Fornitore NIS2 / Fuori ambito / Non determinabile.
    Richiede: ATECO + dipendenti + fascia fatturato.
    is_supplier=True: soggetto fuori ambito che fornisce servizi a entità NIS2.
    """
    if not ateco_code or str(ateco_code).strip().lower() in ('', 'n/d', 'altro', 'none'):
        return {
            "category": "Non determinabile",
            "description": "Compilare ATECO, dipendenti e fascia fatturato per la classificazione",
            "annex": None
        }

    clean = str(ateco_code).replace('.', '').replace(' ', '')

    # PA — sempre Essenziale indipendentemente dalle dimensioni (Art. 3.1.f)
    if clean.startswith('84'):
        return {
            "category": "Essenziale",
            "description": "Pubblica Amministrazione — sempre Essenziale per legge",
            "annex": "I"
        }

    in_annex_i  = any(clean.startswith(p.replace('.', '')) for p in ANNEX_I_PREFIXES)
    in_annex_ii = any(clean.startswith(p.replace('.', '')) for p in ANNEX_II_PREFIXES)

    emp      = _parse_employees(employees_str)
    rev_large, rev_medium = _parse_revenue(revenue_str)

    is_large  = (emp > 250)  or rev_large
    is_medium = (50 <= emp <= 249) or rev_medium

    if in_annex_i:
        if is_large:
            return {"category": "Essenziale",
                    "description": "Grande organizzazione in settore Allegato I NIS2",
                    "annex": "I"}
        elif is_medium:
            return {"category": "Importante",
                    "description": "Media organizzazione in settore Allegato I NIS2",
                    "annex": "I"}
        else:
            if is_supplier:
                return {"category": "Fornitore NIS2",
                        "description": "Piccola impresa in settore NIS2 ma fornitore di soggetti Essenziali/Importanti — Art. 21.2.d",
                        "annex": "I_small"}
            return {"category": "Fuori ambito",
                    "description": "Piccola/micro impresa in settore NIS2 — obblighi non applicabili (salvo eccezioni)",
                    "annex": "I_small"}
    elif in_annex_ii:
        if is_large or is_medium:
            return {"category": "Importante",
                    "description": "Organizzazione in settore Allegato II NIS2",
                    "annex": "II"}
        else:
            if is_supplier:
                return {"category": "Fornitore NIS2",
                        "description": "Piccola impresa in settore secondario NIS2 e fornitore di soggetti NIS2 — Art. 21.2.d",
                        "annex": "II_small"}
            return {"category": "Fuori ambito",
                    "description": "Piccola/micro impresa — NIS2 non applicabile",
                    "annex": "II_small"}
    else:
        if is_supplier:
            return {"category": "Fornitore NIS2",
                    "description": "Settore non direttamente NIS2 ma fornitore di soggetti Essenziali/Importanti — obblighi contrattuali Art. 21.2.d",
                    "annex": None}
        return {"category": "Fuori ambito",
                "description": "Settore non coperto dalla Direttiva NIS2",
                "annex": None}



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
        missing = [h for h, v in headers.items() if v.get("status") == "assente"]
        if missing:
            short_names = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "X-Frame-Options",
                "X-Content-Type-Options": "X-Content-Type-Options",
                "Referrer-Policy": "Referrer-Policy",
                "Permissions-Policy": "Permissions-Policy",
                "Cross-Origin-Opener-Policy": "COOP",
                "Cross-Origin-Resource-Policy": "CORP",
            }
            missing_labels = [short_names.get(h, h) for h in missing[:5]]
            recommendations.append(
                f"Header HTTP mancanti ({len(missing)}): {', '.join(missing_labels)}"
                f"{' e altri' if len(missing) > 5 else ''} (Art. 21.2.a)"
            )

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
    # EMAIL / DNS (max 26 punti)
    # ============================================================

    # MX — record di posta (max 3)
    email_ext = scan_results.get("email_ext", {})
    if email_ext.get("mx_valid"):
        technical_score += 3
        details.append({"area": "MX — server di posta (Art. 21.2.a)", "score": 3, "max": 3,
                         "note": f"{email_ext.get('mx_count', '?')} record MX trovati"})
    else:
        details.append({"area": "MX — server di posta (Art. 21.2.a)", "score": 0, "max": 3,
                         "note": "Nessun record MX trovato"})
        recommendations.append("Verificare la configurazione dei record MX per la posta (Art. 21.2.a)")

    # DMARC (max 8)
    dmarc = scan_results.get("dmarc", {})
    if dmarc.get("presente"):
        policy = dmarc.get("policy", "none")
        if policy == "reject":
            technical_score += 8
            details.append({"area": "DMARC (Art. 21.2.a)", "score": 8, "max": 8, "note": "Policy reject ✓"})
        elif policy == "quarantine":
            technical_score += 5
            details.append({"area": "DMARC (Art. 21.2.a)", "score": 5, "max": 8, "note": "Policy quarantine (consigliato: reject)"})
            recommendations.append("Portare DMARC da quarantine a reject per massima protezione (Art. 21.2.a)")
        else:
            technical_score += 2
            details.append({"area": "DMARC (Art. 21.2.a)", "score": 2, "max": 8, "note": "Policy none — nessuna protezione attiva"})
            recommendations.append("Configurare DMARC con policy quarantine o reject (attuale: none) (Art. 21.2.a)")
    else:
        details.append({"area": "DMARC (Art. 21.2.a)", "score": 0, "max": 8, "note": "Assente — dominio vulnerabile allo spoofing"})
        recommendations.append("Aggiungere record DMARC per proteggere il dominio da spoofing email (Art. 21.2.a)")

    # SPF (max 4)
    spf = scan_results.get("spf", {})
    if spf.get("presente"):
        if not spf.get("softfail", True):   # -all = strict
            technical_score += 4
            details.append({"area": "SPF (Art. 21.2.a)", "score": 4, "max": 4, "note": "Configurato (strict: -all)"})
        else:
            technical_score += 2
            details.append({"area": "SPF (Art. 21.2.a)", "score": 2, "max": 4, "note": "Presente ma permissivo (~all)"})
            recommendations.append("Modificare SPF da ~all (softfail) a -all (hardfail) per protezione completa (Art. 21.2.a)")
    else:
        details.append({"area": "SPF (Art. 21.2.a)", "score": 0, "max": 4, "note": "Assente"})
        recommendations.append("Aggiungere record SPF per autorizzare i server di posta legittimi (Art. 21.2.a)")

    # DKIM (max 5)
    if email_ext.get("dkim_verified"):
        technical_score += 5
        details.append({"area": "DKIM (Art. 21.2.a)", "score": 5, "max": 5,
                         "note": f"Selettore trovato: {email_ext.get('dkim_selector', '?')}"})
    else:
        details.append({"area": "DKIM (Art. 21.2.a)", "score": 0, "max": 5,
                         "note": "Non rilevato (14 selettori comuni verificati)"})
        recommendations.append("Configurare DKIM per firmare digitalmente le email in uscita (Art. 21.2.a)")

    # MTA-STS (max 3)
    if email_ext.get("mta_sts"):
        technical_score += 3
        details.append({"area": "MTA-STS (Art. 21.2.h)", "score": 3, "max": 3, "note": "Abilitato — SMTP cifrato forzato"})
    else:
        details.append({"area": "MTA-STS (Art. 21.2.h)", "score": 0, "max": 3,
                         "note": "Non configurato — SMTP in ingresso non protetto"})
        recommendations.append("Configurare MTA-STS per forzare la cifratura SMTP in ingresso (Art. 21.2.h)")

    # DNSSEC (max 3)
    dnssec = scan_results.get("dnssec", {})
    if dnssec.get("enabled"):
        technical_score += 3
        details.append({"area": "DNSSEC (Art. 21.2.a)", "score": 3, "max": 3, "note": "Abilitato"})
    else:
        details.append({"area": "DNSSEC (Art. 21.2.a)", "score": 0, "max": 3, "note": "Non abilitato"})
        recommendations.append("Abilitare DNSSEC per proteggere i record DNS da avvelenamento (Art. 21.2.a)")

    # ============================================================
    # NUOVI CHECK (max 15 punti)
    # ============================================================

    redirect = scan_results.get("redirect", {})
    if redirect.get("redirects"):
        pts = 3 if redirect.get("permanent") else 2
        technical_score += pts
        details.append({"area": "HTTP→HTTPS redirect (Art. 21.2.h)", "score": pts, "max": 3,
                         "note": "Permanente (301)" if redirect.get("permanent") else "Temporaneo (302)"})
    else:
        details.append({"area": "HTTP→HTTPS redirect (Art. 21.2.h)", "score": 0, "max": 3,
                         "note": "HTTP attivo senza redirect"})
        recommendations.append("Configurare redirect permanente HTTP→HTTPS (Art. 21.2.h)")

    exposed_files = scan_results.get("exposed_files", {})
    if exposed_files.get("safe", True):
        technical_score += 3
        details.append({"area": "File sensibili (Art. 21.2.e)", "score": 3, "max": 3,
                         "note": "Nessun file sensibile esposto"})
    else:
        count = exposed_files.get("count", 0)
        exposed = ", ".join(exposed_files.get("exposed", [])[:3])
        details.append({"area": "File sensibili (Art. 21.2.e)", "score": 0, "max": 3,
                         "note": f"{count} file esposti: {exposed}"})
        recommendations.append(f"Rimuovere file sensibili esposti: {exposed} (Art. 21.2.e)")

    tls = scan_results.get("tls_version", {})
    if tls.get("secure"):
        pts = 5 if tls.get("supports_tls13") else 3
        technical_score += pts
        ver_note = tls.get("version", "sicura")
        if tls.get("supports_tls13"):
            ver_note += " — TLS 1.3 supportato"
        details.append({"area": "Versione TLS (Art. 21.2.h)", "score": pts, "max": 5, "note": ver_note})
    else:
        details.append({"area": "Versione TLS (Art. 21.2.h)", "score": 0, "max": 5,
                         "note": f"Versione deprecata: {tls.get('version', 'sconosciuta')}"})
        recommendations.append("Aggiornare a TLS 1.2/1.3 e disabilitare protocolli obsoleti (Art. 21.2.h)")

    subdomain = scan_results.get("subdomain", {})
    if subdomain.get("safe", True):
        technical_score += 4
        details.append({"area": "Subdomain takeover (Art. 21.2.e)", "score": 4, "max": 4,
                         "note": "Nessun CNAME pendente rilevato"})
    else:
        count = subdomain.get("count", 0)
        dangling = [d["subdomain"] for d in subdomain.get("dangling", [])[:2]]
        details.append({"area": "Subdomain takeover (Art. 21.2.e)", "score": 0, "max": 4,
                         "note": f"{count} CNAME pendente/i: {', '.join(dangling)}"})
        recommendations.append(f"Risolvere CNAME pendenti: {', '.join(dangling)} (Art. 21.2.e)")

    # nis2_info serve anche nel questionario per pesare i gap
    nis2_info = get_nis2_category(
        company_data.get("ateco", ""),
        company_data.get("employees", ""),
        company_data.get("revenue", ""),
        is_supplier=bool(company_data.get("is_supplier", False))
    )

    # Seleziona le domande appropriate per la categoria rilevata
    _cat = nis2_info.get("category", "Fuori ambito")
    question_map = QUESTION_MAP_BY_CATEGORY.get(_cat, QUESTION_MAP_BY_CATEGORY["Fuori ambito"])

    # ============================================================
    # QUESTIONARIO (max varia per categoria: 30pt Ess., 21pt Imp., 9pt Fuori)
    # ============================================================
    questionnaire_score = 0
    questionnaire_details = []

    questionnaire_gaps = []
    if questions:
        for key, info in question_map.items():
            answer = questions.get(key, "no")
            label_str = f"{info['label']} ({info['art']})"
            if answer in ["si", "si_interno", "si_esterno", "iso27001", "altra"]:
                questionnaire_score += 3
                questionnaire_details.append({"question": label_str, "answer": "si"})
            elif answer in ["parziale", "saltuaria", "in_corso"]:
                questionnaire_score += 1.5
                questionnaire_details.append({"question": label_str, "answer": "parziale"})
                base_weight = info.get("weight", "MEDIO")
                weight = {"CRITICO": "ALTO", "ALTO": "MEDIO", "MEDIO": "BASSO"}.get(base_weight, "BASSO")
                questionnaire_gaps.append({
                    "key": key, "label": info["label"], "art": info["art"],
                    "answer": "parziale", "weight": weight,
                    "consequence": info.get("consequence", ""),
                    "portable": info.get("portable", "")
                })
            else:
                questionnaire_details.append({"question": label_str, "answer": "no"})
                questionnaire_gaps.append({
                    "key": key, "label": info["label"], "art": info["art"],
                    "answer": "no", "weight": info.get("weight", "MEDIO"),
                    "consequence": info.get("consequence", ""),
                    "portable": info.get("portable", "")
                })

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

    _cat = nis2_info["category"]
    if _cat == "Essenziale" and total_score < 50:
        overall_risk, risk_color = "CRITICO", "error"
    elif _cat == "Essenziale" and total_score < 75:
        overall_risk, risk_color = "ALTO", "warning"
    elif _cat == "Importante" and total_score < 40:
        overall_risk, risk_color = "CRITICO", "error"
    elif _cat == "Importante" and total_score < 60:
        overall_risk, risk_color = "ALTO", "warning"
    elif _cat == "Fornitore NIS2" and total_score < 40:
        overall_risk, risk_color = "CRITICO", "error"   # 3 domande critiche senza risposta
    elif _cat == "Fornitore NIS2" and total_score < 65:
        overall_risk, risk_color = "ALTO", "warning"    # gap contrattuali da colmare
    elif _cat == "Fornitore NIS2" and total_score < 80:
        overall_risk, risk_color = "MEDIO", "warning"
    elif total_score >= 80:
        overall_risk, risk_color = "BASSO", "ok"
    elif total_score >= 50:
        overall_risk, risk_color = "MEDIO", "warning"
    else:
        overall_risk, risk_color = "CRITICO", "error"


    # Ordina gaps per priorità: CRITICO > ALTO > MEDIO > BASSO
    _order = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BASSO": 3}
    questionnaire_gaps.sort(key=lambda g: _order.get(g["weight"], 4))

    # NIS2 Readiness breakdown (sostituisce ISO 27001 simulato)
    tech_max   = sum(d.get("max", 0) for d in details)
    quest_max  = len(question_map) * 3
    nis2_readiness = {
        "tech_score":   round(technical_score, 1),
        "tech_max":     tech_max,
        "quest_score":  round(questionnaire_score, 1),
        "quest_max":    quest_max,
        "ciso_score":   ciso_score,
        "email_score":  email_score,
        "critical_gaps": [g["label"] for g in questionnaire_gaps if g["weight"] == "CRITICO"],
        "high_gaps":     [g["label"] for g in questionnaire_gaps if g["weight"] == "ALTO"],
    }

    return {
        "total_score": total_score,
        "nis2_category": nis2_info,
        "overall_risk": overall_risk,
        "risk_color": risk_color,
        "details": details,
        "questionnaire_details": questionnaire_details,
        "questionnaire_gaps": questionnaire_gaps,
        "recommendations": recommendations,
        "nis2_readiness": nis2_readiness,
    }