import ssl
import socket
import dns.resolver
import requests
from datetime import datetime
import re

# Timeout globali (secondi)
_CONNECT_TIMEOUT = 5
_HTTP_TIMEOUT = 10
_DNS_LIFETIME = 3


def scan_domain(domain):
    """
    Esegue scan tecnici sul dominio aziendale.
    Restituisce un dizionario con tutti i risultati.
    """
    results = {
        "ssl":            check_ssl(domain),
        "headers":        check_security_headers(domain),
        "dmarc":          check_dmarc(domain),
        "spf":            check_spf(domain),
        "dnssec":         check_dnssec(domain),
        "cms":            detect_cms(domain),
        "waf":            detect_waf(domain),
        "email_ext":      check_email_extended(domain),
        "redirect":       check_http_redirect(domain),
        "exposed_files":  check_exposed_files(domain),
        "tls_version":    check_tls_version(domain),
        "subdomain":      check_subdomain_takeover(domain),
    }
    return results


# ============================================================
# CHECK ESISTENTI — corretti
# ============================================================

def check_ssl(domain):
    """Verifica validità certificato SSL e giorni alla scadenza."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'],  "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days
                issuer = dict(x[0] for x in cert.get('issuer', []))
                return {
                    "valid": True,
                    "days_left": days_left,
                    "issuer": issuer.get('organizationName', 'Sconosciuto'),
                    "status": "ok" if days_left > 30 else "warning" if days_left > 0 else "expired"
                }
    except Exception:
        return {"valid": False, "status": "error"}


def check_security_headers(domain):
    """Verifica gli header HTTP di sicurezza."""
    headers_to_check = {
        "Strict-Transport-Security":    "HSTS assente — rischio attacchi MITM",
        "Content-Security-Policy":      "CSP assente — rischio XSS/injection",
        "X-Frame-Options":              "Protezione clickjacking assente",
        "X-Content-Type-Options":       "Protezione MIME sniffing assente",
        "Referrer-Policy":              "Referrer-Policy assente — possibile info leak",
        "Permissions-Policy":           "Permissions-Policy assente — API browser non controllate",
        "Cross-Origin-Opener-Policy":   "COOP assente — rischio attacchi cross-origin",
        "Cross-Origin-Resource-Policy": "CORP assente — risorse accessibili da altri domini",
    }
    results = {}
    try:
        response = requests.get(
            f"https://{domain}", timeout=_HTTP_TIMEOUT, allow_redirects=True
        )
        for header, message in headers_to_check.items():
            if header in response.headers:
                results[header] = {
                    "status": "presente",
                    "value": response.headers[header][:100]
                }
            else:
                results[header] = {"status": "assente", "value": message}
    except Exception:
        for header in headers_to_check:
            results[header] = {"status": "errore", "value": "Impossibile verificare"}
    return results


def check_dmarc(domain):
    """Verifica record DMARC e policy."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=_DNS_LIFETIME)
        for rdata in answers:
            text = str(rdata)
            if "v=DMARC1" in text:
                policy = "none"
                if "p=reject" in text:
                    policy = "reject"
                elif "p=quarantine" in text:
                    policy = "quarantine"
                return {"presente": True, "policy": policy, "record": text[:200]}
        return {"presente": False, "policy": "nessuna"}
    except Exception:
        return {"presente": False, "policy": "nessuna"}


def check_spf(domain):
    """Verifica record SPF."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=_DNS_LIFETIME)
        for rdata in answers:
            text = str(rdata)
            if "v=spf1" in text:
                softfail = "~all" in text
                return {
                    "presente": True,
                    "record": text[:200],
                    "softfail": softfail
                }
        return {"presente": False}
    except Exception:
        return {"presente": False}


def check_email_extended(domain):
    """
    Verifica MX, DKIM (14 selettori comuni) e MTA-STS.
    Complementa i check DMARC/SPF/DNSSEC già presenti.
    """
    result = {
        "mx_valid": False, "mx_count": 0,
        "dkim_verified": False, "dkim_selector": "",
        "mta_sts": False,
    }

    # MX
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX', lifetime=_DNS_LIFETIME)
        result["mx_valid"] = True
        result["mx_count"] = len(list(mx_answers))
    except Exception:
        pass

    # DKIM — selettori più comuni
    dkim_selectors = [
        "default", "google", "mail", "smtp", "dkim",
        "selector1", "selector2",  # Microsoft 365
        "k1", "k2",                # Mailchimp/Mandrill
        "s1", "s2",
        "email",                   # SendGrid
        "mx",                      # Zoho
        "protonmail", "amazonses",
    ]
    for sel in dkim_selectors:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", 'TXT', lifetime=2)
            result["dkim_verified"] = True
            result["dkim_selector"] = sel
            break
        except Exception:
            continue

    # MTA-STS (RFC 8461)
    try:
        for rdata in dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT', lifetime=_DNS_LIFETIME):
            if "v=STSv1" in str(rdata):
                result["mta_sts"] = True
                break
    except Exception:
        pass

    return result


def check_dnssec(domain):
    """Verifica se DNSSEC è abilitato."""
    try:
        parts = domain.split('.')
        main_domain = '.'.join(parts[-2:]) if len(parts) > 2 else domain
        dns.resolver.resolve(main_domain, 'DNSKEY', lifetime=_DNS_LIFETIME)
        return {"enabled": True, "message": "DNSSEC abilitato"}
    except Exception:
        return {"enabled": False, "message": "DNSSEC non rilevato — rischio avvelenamento DNS"}


def detect_cms(domain):
    """
    Rileva CMS e tecnologie esposte e popola la lista 'risks'
    usata dal motore di scoring.
    """
    result = {"detected": [], "risks": []}
    try:
        response = requests.get(
            f"https://{domain}", timeout=_HTTP_TIMEOUT, allow_redirects=True
        )
        html = response.text.lower()
        headers = response.headers

        # WordPress
        if "wp-content" in html or "wp-includes" in html:
            result["detected"].append("WordPress")
            # Versione esposta nel meta generator
            version_match = re.search(r'<meta[^>]+generator[^>]+wordpress\s+([\d.]+)', html)
            if version_match:
                ver = version_match.group(1)
                result["risks"].append(f"WordPress versione {ver} esposta nel sorgente")
            # Pannello admin esposto
            try:
                admin_resp = requests.get(
                    f"https://{domain}/wp-login.php", timeout=5, allow_redirects=False
                )
                if admin_resp.status_code == 200:
                    result["risks"].append("Pannello admin WordPress (/wp-login.php) accessibile")
            except Exception:
                pass

        # Joomla
        if "joomla" in html or "option=com_" in html:
            result["detected"].append("Joomla")
            try:
                admin_resp = requests.get(
                    f"https://{domain}/administrator/", timeout=5, allow_redirects=False
                )
                if admin_resp.status_code == 200:
                    result["risks"].append("Pannello admin Joomla (/administrator/) accessibile")
            except Exception:
                pass

        # Drupal
        if "drupal" in html or "sites/all/" in html or "sites/default/" in html:
            result["detected"].append("Drupal")

        # Server disclosure
        server = headers.get('Server', '')
        if server:
            # Versione specifica esposta (es. "Apache/2.4.51") è un rischio
            if re.search(r'[\d.]{3,}', server):
                result["risks"].append(f"Versione server esposta nell'header: {server[:60]}")
            if 'nginx' in server.lower():
                result["detected"].append("Nginx")
            if 'apache' in server.lower():
                result["detected"].append("Apache")

        # PHP version disclosure
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            result["detected"].append(f"PHP ({powered_by})")
            result["risks"].append(f"Versione PHP esposta nell'header X-Powered-By: {powered_by[:60]}")

        if not result["detected"]:
            result["detected"].append("Nessun CMS/tecnologia riconosciuta")

    except Exception:
        result["detected"].append("Rilevamento CMS non riuscito")

    return result


# ============================================================
# WAF — mancante, aggiunto
# ============================================================

def detect_waf(domain):
    """
    Rileva la presenza di un WAF analizzando header e comportamento
    del server di fronte a payload sospetti.
    """
    waf_signatures = {
        'Cloudflare':  ['cf-ray', 'cf-cache-status'],
        'Sucuri':      ['x-sucuri-id', 'x-sucuri-cache'],
        'Akamai':      ['x-akamai-transformed', 'akamai-cache-status'],
        'AWS WAF':     ['x-amzn-requestid', 'x-amz-cf-id'],
        'Imperva':     ['x-cdn', 'x-iinfo'],
        'Barracuda':   ['barra_counter_session'],
        'Fastly':      ['x-fastly-request-id'],
    }
    try:
        response = requests.get(f"https://{domain}", timeout=_HTTP_TIMEOUT)
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        for provider, signatures in waf_signatures.items():
            if any(sig in resp_headers for sig in signatures):
                return {"protected": True, "provider": provider}

        # Test comportamentale: richiesta con payload XSS
        test_url = f"https://{domain}/?q=<script>alert(1)</script>"
        test_resp = requests.get(test_url, timeout=5, allow_redirects=False)
        if test_resp.status_code in (403, 406, 429, 503):
            return {"protected": True, "provider": "Sconosciuto (blocco rilevato)"}

    except Exception:
        pass

    return {"protected": False, "provider": None}


# ============================================================
# NUOVI CHECK
# ============================================================

def check_http_redirect(domain):
    """
    Verifica che HTTP forzi il redirect a HTTPS (Art. 21.2.h).
    Controlla anche che il redirect sia permanente (301/308).
    """
    try:
        response = requests.get(
            f"http://{domain}", timeout=_HTTP_TIMEOUT, allow_redirects=False
        )
        code = response.status_code
        location = response.headers.get('Location', '')
        if code in (301, 302, 307, 308) and location.startswith('https://'):
            return {
                "redirects": True,
                "permanent": code in (301, 308),
                "code": code,
                "note": "Redirect HTTPS corretto"
            }
        return {
            "redirects": False,
            "code": code,
            "note": "HTTP attivo senza redirect a HTTPS"
        }
    except Exception:
        return {"redirects": False, "note": "Verifica non riuscita"}


def check_exposed_files(domain):
    """
    Verifica l'accessibilità pubblica di file sensibili (Art. 21.2.e).
    Restituisce la lista dei file esposti trovati.
    """
    sensitive_paths = [
        '.env',
        '.git/config',
        'phpinfo.php',
        'backup.zip',
        'backup.sql',
        'dump.sql',
        'wp-config.php.bak',
        'config.php.bak',
        '.htaccess',
        'web.config.bak',
        'composer.json',
        'package.json',
        'Dockerfile',
    ]
    exposed = []
    for path in sensitive_paths:
        try:
            r = requests.get(
                f"https://{domain}/{path}",
                timeout=5,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            # 200 + contenuto non banale = file esposto
            if r.status_code == 200 and len(r.content) > 20:
                exposed.append(path)
        except Exception:
            pass
    return {
        "exposed": exposed,
        "count": len(exposed),
        "safe": len(exposed) == 0
    }


def check_tls_version(domain):
    """
    Verifica la versione TLS negoziata e segnala protocolli deprecati
    (Art. 21.2.h — standard crittografici).
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version()   # es. 'TLSv1.3', 'TLSv1.2'
                secure = version in ('TLSv1.2', 'TLSv1.3')
                return {
                    "version": version,
                    "secure": secure,
                    "supports_tls13": version == 'TLSv1.3',
                    "note": "Versione sicura" if secure else f"Versione deprecata: {version}"
                }
    except Exception:
        return {"version": "sconosciuta", "secure": False, "supports_tls13": False}


def check_subdomain_takeover(domain):
    """
    Rileva sottodomini con record CNAME pendenti (dangling CNAME)
    vulnerabili a subdomain takeover (Art. 21.2.e).
    """
    common_subdomains = [
        'www', 'mail', 'webmail', 'ftp', 'vpn', 'admin',
        'api', 'dev', 'staging', 'test', 'beta', 'app',
        'portal', 'shop', 'cdn', 'status',
    ]
    dangling = []
    for sub in common_subdomains:
        fqdn = f"{sub}.{domain}"
        try:
            cname_answers = dns.resolver.resolve(fqdn, 'CNAME', lifetime=_DNS_LIFETIME)
            for rdata in cname_answers:
                target = str(rdata.target).rstrip('.')
                # CNAME presente: verifica se il target è ancora attivo
                try:
                    dns.resolver.resolve(target, 'A', lifetime=_DNS_LIFETIME)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    dangling.append({"subdomain": fqdn, "cname": target})
        except Exception:
            pass   # sottodominio inesistente o nessun CNAME: ok

    return {
        "dangling": dangling,
        "count": len(dangling),
        "safe": len(dangling) == 0
    }
