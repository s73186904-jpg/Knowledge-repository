import ipaddress
from urllib.parse import urlparse
import requests
import whois
import streamlit as st

def validate_target(target_type: str, target: str) -> bool:
    """Validates the target based on its type."""
    target = target.strip()
    if not target:
        return False
    
    if target_type == "IP Address":
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
            
    elif target_type == "Domain":
        if "." in target and " " not in target:
            return True
        return False
        
    elif target_type == "URL":
        try:
            parsed = urlparse(target)
            return bool(parsed.netloc) and bool(parsed.scheme)
        except Exception:
            return False
            
    return False

def get_virustotal(target_type: str, target: str) -> dict:
    """Fetches threat intelligence report from VirusTotal API."""
    api_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"error": "Missing VIRUSTOTAL_API_KEY in Streamlit secrets."}
    
    headers = {"x-apikey": api_key}
    
    try:
        if target_type == "IP Address":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        elif target_type == "Domain":
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
        else:
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "raw": stats
            }
        else:
            return {"error": f"VirusTotal API error: Status code {response.status_code}"}
    except Exception as e:
        return {"error": f"VirusTotal connection failed: {str(e)}"}

def get_whois(target_type: str, target: str) -> dict:
    """Fetches WHOIS registration details for domains or URLs."""
    if target_type == "URL":
        parsed = urlparse(target)
        target = parsed.netloc or target
        
    if target_type == "IP Address":
        return {"info": "WHOIS lookup is primarily designed for Domains."}
        
    try:
        w = whois.whois(target)
        return {
            "source": "WHOIS",
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": str(w.name_servers)
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed or unsupported for this target: {str(e)}"}

# SOURCES Registry mapping source names to their respective function handles
SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois
}
