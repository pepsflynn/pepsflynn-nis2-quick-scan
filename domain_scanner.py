import ssl
import socket
import dns.resolver
import requests
from datetime import datetime
import re

def scan_domain(domain):
    """
    Esegue scan tecnici avanzati sul dominio aziendale.
    Restituisce un dizionario con tutti i risultati.
    """
    results = {
        "ssl": check_ssl(domain),
        "headers": check_security_headers(domain),
        "dmarc": check_dmarc(domain),
        "spf": check_spf(domain),
        "breach": check_breach(domain),
        "cms": detect_cms(domain),
        "cookies": check_cookies(domain),
        "ports": check_common_ports(domain),
        "dnssec": check_dnssec(domain)
    }
    return results

def check_ssl(domain):
    """Verifica validita' certificato SSL e dettagli"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                issued = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days
                issuer = dict(x[0] for x in cert.get('issuer', []))
                return {
                    "valid": True,
                    "days_left": days_left,
                    "issuer": issuer.get('organizationName', 'Sconosciuto'),
                    "status": "ok" if days_left > 30 else "warning" if days_left > 0 else "expired"
                }
    except:
        return {"valid": False, "status": "error"}

def check_security_headers(domain):
    """Verifica header di sicurezza HTTP estesi"""
    headers_to_check = {
        "Strict-Transport-Security": "HSTS assente - Rischio attacchi man-in-the-middle",
        "Content-Security-Policy": "CSP assente - Rischio attacchi XSS e injection",
        "X-Frame-Options": "Protezione clickjacking assente",
        "X-Content-Type-Options": "Protezione MIME sniffing assente",
        "Referrer-Policy": "Referrer-Policy assente - Possibile leak di informazioni",
        "Permissions-Policy": "Permissions-Policy assente - API browser non controllate",
        "Cross-Origin-Opener-Policy": "COOP assente - Rischio attacchi cross-origin",
        "Cross-Origin-Resource-Policy": "CORP assente - Risorse accessibili da altri domini"
    }
    
    results = {}
    try:
        response = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
        for header, message in headers_to_check.items():
            if header in response.headers:
                results[header] = {"status": "presente", "value": response.headers[header][:100]}
            else:
                results[header] = {"status": "assente", "value": message}
    except:
        for header in headers_to_check:
            results[header] = {"status": "errore", "value": "Impossibile verificare"}
    
    return results

def check_dmarc(domain):
    """Verifica record DMARC e policy"""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            text = str(rdata)
            if "v=DMARC1" in text:
                policy = "none"
                if "p=reject" in text:
                    policy = "reject"
                elif "p=quarantine" in text:
                    policy = "quarantine"
                return {
                    "presente": True,
                    "policy": policy,
                    "record": text[:200]
                }
        return {"presente": False, "policy": "nessuna"}
    except:
        return {"presente": False, "policy": "nessuna", "errore": "Record DMARC non trovato"}

def check_spf(domain):
    """Verifica record SPF"""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            text = str(rdata)
            if "v=spf1" in text:
                return {"presente": True, "record": text[:200]}
        return {"presente": False}
    except:
        return {"presente": False, "errore": "Record SPF non trovato"}

def check_breach(domain):
    """
    Verifica se il dominio appare in data breach pubblici.
    Usa l'API gratuita di Have I Been Pwned (metodo sicuro con k-anonymity).
    """
    # Metodo semplificato: verifichiamo se ci sono risultati noti
    # In produzione useremmo l'API k-anonymity di HIBP
    try:
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
        headers = {"User-Agent": "NIS2-QuickScan"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            breaches = response.json()
            if breaches:
                breach_names = [b.get('Name', 'Sconosciuto') for b in breaches[:5]]
                return {
                    "found": True,
                    "count": len(breaches),
                    "breaches": breach_names,
                    "message": f"Dominio trovato in {len(breaches)} data breach noti!"
                }
        return {"found": False, "count": 0, "message": "Nessun data breach pubblico trovato"}
    except:
        return {"found": False, "count": 0, "message": "Verifica non riuscita"}

def detect_cms(domain):
    """
    Rileva CMS e tecnologie dal sito web.
    Verifica WordPress, Joomla, Drupal, ecc.
    """
    result = {"detected": [], "versioni": {}}
    
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        html = response.text.lower()
        headers = response.headers
        
        # WordPress
        if "wp-content" in html or "wp-includes" in html:
            result["detected"].append("WordPress")
            # Cerca versione nel meta generator
            version_match = re.search(r'wordpress (\d+\.\d+\.\d+)', html)
            if version_match:
                result["versioni"]["WordPress"] = version_match.group(1)
        
        # Joomla
        if "joomla" in html or "option=com_" in html:
            result["detected"].append("Joomla")
        
        # Drupal
        if "drupal" in html or 'sites/all/' in html or 'sites/default/' in html:
            result["detected"].append("Drupal")
        
        # Nginx/Apache detection
        server = headers.get('Server', '')
        if 'nginx' in server.lower():
            result["detected"].append("Nginx")
        if 'apache' in server.lower():
            result["detected"].append("Apache")
        
        # PHP detection
        if 'x-powered-by' in headers:
            result["detected"].append(f"PHP ({headers['x-powered-by']})")
        
        if not result["detected"]:
            result["detected"].append("Nessun CMS/tecnologia riconosciuta")
    
    except:
        result["detected"].append("Rilevamento CMS non riuscito")
    
    return result

def check_cookies(domain):
    """
    Verifica la presenza di cookie di sessione con flag di sicurezza.
    """
    result = {"secure_cookies": 0, "httponly_cookies": 0, "samesite_cookies": 0, "total_cookies": 0}
    
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        cookies = response.cookies
        result["total_cookies"] = len(cookies)
        
        for cookie in cookies:
            if cookie.secure:
                result["secure_cookies"] += 1
            if cookie.has_nonstandard_attr('HttpOnly'):
                result["httponly_cookies"] += 1
            if cookie.has_nonstandard_attr('SameSite'):
                result["samesite_cookies"] += 1
    except:
        pass
    
    return result

def check_common_ports(domain):
    """
    Verifica porte comuni aperte (scan rapido).
    """
    common_ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }
    
    open_ports = []
    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append({"port": port, "service": service})
            sock.close()
        except:
            pass
    
    return {
        "open_ports": open_ports,
        "count": len(open_ports),
        "risk": "Alto" if len(open_ports) > 5 else "Medio" if len(open_ports) > 3 else "Basso"
    }

def check_dnssec(domain):
    """
    Verifica se il dominio ha DNSSEC abilitato.
    """
    try:
        # Estrai il dominio principale
        parts = domain.split('.')
        if len(parts) > 2:
            main_domain = '.'.join(parts[-2:])
        else:
            main_domain = domain
        
        answers = dns.resolver.resolve(main_domain, 'DNSKEY')
        if answers:
            return {"enabled": True, "message": "DNSSEC abilitato sul dominio"}
    except:
        pass
    
    return {"enabled": False, "message": "DNSSEC non rilevato - Rischio avvelenamento DNS"}