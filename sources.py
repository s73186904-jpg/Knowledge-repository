"""
sources.py

Intelligence-source functions for ThreatLens.

Each source function accepts a normalized target + target_type and returns
a consistent result dictionary:

    {
        "source": "<Name>",
        "success": bool,
        "data": {...},
        "error": Optional[str],
    }

Rules for this file:
- No Streamlit / UI code.
- No Gemini calls.
- No imports from app.py (one-way dependency: app.py -> sources.py).
- Each function calls only its own external service and handles its own
  errors gracefully (never raises out to the caller).
"""

from __future__ import annotations

import os
from typing import Callable
from urllib.parse import urlparse

import requests

try:
    import whois as python_whois  # python-whois package
except ImportError:  # pragma: no cover - surfaced as a runtime error dict instead
    python_whois = None


VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT_SECONDS = 15


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _result(source: str, success: bool, data: dict | None = None, error: str | None = None) -> dict:
    return {
        "source": source,
        "success": success,
        "data": data or {},
        "error": error,
    }


def _extract_hostname(target: str, target_type: str) -> str:
    """Return the bare hostname/domain to use for domain-oriented lookups."""
    if target_type == "URL":
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


# --------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------

def get_virustotal(target: str, target_type: str) -> dict:
    """Query VirusTotal for reputation/detection info on an IP, domain, or URL."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return _result("VirusTotal", False, error="Missing VIRUSTOTAL_API_KEY environment variable.")

    headers = {"x-apikey": api_key}

    try:
        if target_type == "IP Address":
            url = f"{VIRUSTOTAL_API_BASE}/ip_addresses/{target}"
        elif target_type == "Domain":
            url = f"{VIRUSTOTAL_API_BASE}/domains/{target}"
        elif target_type == "URL":
            # VirusTotal requires a URL identifier: base64 (no padding) of the URL.
            import base64

            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"{VIRUSTOTAL_API_BASE}/urls/{url_id}"
        else:
            return _result("VirusTotal", False, error=f"Unsupported target type: {target_type}")

        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)

        if response.status_code == 401:
            return _result("VirusTotal", False, error="Invalid or unauthorized VirusTotal API key.")
        if response.status_code == 404:
            return _result(
                "VirusTotal",
                True,
                data={"found": False, "message": "No VirusTotal record found for this target."},
            )
        if not response.ok:
            return _result("VirusTotal", False, error=f"VirusTotal API error (HTTP {response.status_code}).")

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        data = {
            "found": True,
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"),
            "undetected": stats.get("undetected"),
            "timeout": stats.get("timeout"),
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "categories": attributes.get("categories"),
            "tags": attributes.get("tags"),
        }

        if target_type == "Domain":
            data["registrar"] = attributes.get("registrar")
        if target_type == "IP Address":
            data["as_owner"] = attributes.get("as_owner")
            data["country"] = attributes.get("country")
        if target_type == "URL":
            data["final_url"] = attributes.get("last_final_url")
            data["title"] = attributes.get("title")

        # Drop empty keys to keep the payload compact.
        data = {k: v for k, v in data.items() if v not in (None, {}, [])}

        return _result("VirusTotal", True, data=data)

    except requests.exceptions.Timeout:
        return _result("VirusTotal", False, error="VirusTotal request timed out.")
    except requests.exceptions.RequestException as exc:
        return _result("VirusTotal", False, error=f"Network error contacting VirusTotal: {exc}")
    except (ValueError, KeyError) as exc:
        return _result("VirusTotal", False, error=f"Could not parse VirusTotal response: {exc}")
    except Exception as exc:  # noqa: BLE001 - never let a source crash the app
        return _result("VirusTotal", False, error=f"Unexpected VirusTotal error: {exc}")


# --------------------------------------------------------------------------
# WHOIS
# --------------------------------------------------------------------------

def get_whois(target: str, target_type: str) -> dict:
    """Retrieve registration information for a domain (or the domain behind a URL)."""
    if python_whois is None:
        return _result("WHOIS", False, error="python-whois package is not installed.")

    if target_type == "IP Address":
        return _result(
            "WHOIS",
            True,
            data={"note": "WHOIS/RDAP lookups for raw IP addresses are limited or unsupported here."},
        )

    hostname = _extract_hostname(target, target_type)

    try:
        record = python_whois.whois(hostname)

        if not record or not getattr(record, "domain_name", None):
            return _result(
                "WHOIS",
                True,
                data={"found": False, "message": "No WHOIS record found for this domain."},
            )

        def _first(value):
            if isinstance(value, list):
                return value[0] if value else None
            return value

        data = {
            "found": True,
            "registrar": _first(record.registrar) if hasattr(record, "registrar") else None,
            "creation_date": str(_first(record.creation_date)) if getattr(record, "creation_date", None) else None,
            "expiration_date": str(_first(record.expiration_date)) if getattr(record, "expiration_date", None) else None,
            "updated_date": str(_first(record.updated_date)) if getattr(record, "updated_date", None) else None,
            "organization": _first(record.org) if hasattr(record, "org") else None,
            "name_servers": record.name_servers if getattr(record, "name_servers", None) else None,
            "status": record.status if getattr(record, "status", None) else None,
            "country": _first(record.country) if hasattr(record, "country") else None,
        }

        data = {k: v for k, v in data.items() if v not in (None, {}, [])}

        return _result("WHOIS", True, data=data)

    except Exception as exc:  # noqa: BLE001 - WHOIS libraries raise many varied errors
        return _result("WHOIS", False, error=f"WHOIS lookup failed: {exc}")


# --------------------------------------------------------------------------
# Source registry
# --------------------------------------------------------------------------
# app.py must iterate over this dict rather than calling source functions
# directly. To add a new source, implement `def get_x(target, target_type)
# -> dict` above and register it here — no other file needs to change.

SOURCES: dict[str, Callable[[str, str], dict]] = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
