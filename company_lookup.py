import requests

def lookup_company(vat_number):
    """
    Recupera i dati aziendali da Partita IVA italiana usando diverse fonti.
    Priorità: OpenCorporates (Open Data), poi VIES (UE), poi API pubblica.
    """
    vat_number = ''.join(filter(str.isdigit, vat_number))

    # 1. Fonte OpenCorporates (API Key gratuita)
    # Sostituisci 'IL_TUO_API_KEY' dopo esserti registrato su opencorporates.com
    OPENCORPORATES_KEY = "IL_TUO_API_KEY" 
    if OPENCORPORATES_KEY != "IL_TUO_API_KEY":
        try:
            # Il codice 'it' indica che stiamo cercando un'azienda in Italia
            url = f"https://api.opencorporates.com/v0.4/companies/it/{vat_number}"
            response = requests.get(url, params={"api_token": OPENCORPORATES_KEY}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                company = data.get('results', {}).get('company', {})
                if company:
                    return {
                        "name": company.get('name', 'N/D'),
                        "ateco": company.get('industry_code', 'N/D')[1:], # Estrae codice ATECO
                        "employees": 'N/D', # OpenCorporates non fornisce dipendenti
                        "address": company.get('registered_address_in_full', 'N/D'),
                        "status": "success",
                        "source": "opencorporates"
                    }
        except Exception as e:
            print(f"Errore OpenCorporates: {e}")

    # 2. Fonte VIES (UE) - validazione e nome
    try:
        url = f"https://ec.europa.eu/taxation_customs/vies/rest-api/ms/IT/vat/{vat_number}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("isValid"):
                return {
                    "name": data.get("name", "N/D"),
                    "ateco": "N/D",
                    "employees": "N/D",
                    "address": data.get("address", "N/D"),
                    "status": "success",
                    "source": "vies"
                }
    except Exception as e:
        print(f"Errore VIES: {e}")

    return None