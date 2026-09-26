"""
app.py

ThreatLens — a lightweight Streamlit app that checks whether an IP address,
domain, or URL looks safe, suspicious, or malicious using VirusTotal + WHOIS,
with Gemini used only to interpret and explain the collected results.

This file owns: UI, input validation, source orchestration, Gemini prompt
construction/calling, verdict display, and result rendering. All
source-specific logic lives in sources.py; this file only consumes the
generic SOURCES registry.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from urllib.parse import urlparse

import streamlit as st

from sources import SOURCES

try:
    from google import genai
except ImportError:  # handled gracefully at call time
    genai = None


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def validate_target(target: str, target_type: str) -> tuple[bool, str]:
    """Return (is_valid, error_message_or_normalized_target)."""
    target = target.strip()
    if not target:
        return False, "Please enter a target."

    if target_type == "IP Address":
        try:
            ipaddress.ip_address(target)
            return True, target
        except ValueError:
            return False, "That doesn't look like a valid IPv4 or IPv6 address."

    if target_type == "Domain":
        candidate = target.lower().rstrip(".")
        if _DOMAIN_RE.match(candidate):
            return True, candidate
        return False, "That doesn't look like a valid domain (e.g. example.com)."

    if target_type == "URL":
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return False, "URL must start with http:// or https://."
        if not parsed.hostname:
            return False, "URL is missing a valid hostname."
        return True, target

    return False, f"Unknown target type: {target_type}"


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def collect_source_results(target: str, target_type: str) -> dict[str, dict]:
    """Run every registered source and collect its normalized result.

    Iterates over sources.SOURCES generically so that new sources need no
    changes here.
    """
    results: dict[str, dict] = {}
    for source_name, source_function in SOURCES.items():
        try:
            results[source_name] = source_function(target, target_type)
        except Exception as exc:  # noqa: BLE001 - a broken source must not crash the app
            results[source_name] = {
                "source": source_name,
                "success": False,
                "data": {},
                "error": f"Unexpected error running this source: {exc}",
            }
    return results


# --------------------------------------------------------------------------
# Gemini prompting
# --------------------------------------------------------------------------

LEVEL_INSTRUCTIONS = {
    "Beginner": (
        "Write for a beginner. Avoid unnecessary cybersecurity terminology. "
        "Explain findings in plain language, clearly explain why the target "
        "may or may not be dangerous, and give simple recommended actions."
    ),
    "Intermediate": (
        "Write for someone with intermediate security knowledge. Use common "
        "cybersecurity terminology, explain important indicators and how "
        "they relate to each other, discuss meaningful technical findings, "
        "and provide practical mitigation/review steps."
    ),
    "Expert": (
        "Write for an expert. Be concise and technically detailed. Focus on "
        "indicators, reputation, registration data, detection ratios, "
        "infrastructure clues, and uncertainty. Avoid explaining basic "
        "concepts unless necessary. Clearly distinguish observed facts from "
        "inference."
    ),
}


def build_gemini_prompt(target: str, target_type: str, knowledge_level: str, results: dict[str, dict]) -> str:
    instructions = LEVEL_INSTRUCTIONS.get(knowledge_level, LEVEL_INSTRUCTIONS["Intermediate"])

    return f"""You are analyzing external security intelligence collected about a target.
You are NOT a threat-intelligence data source yourself — you only interpret
the data provided below, which was gathered from VirusTotal and WHOIS (and
possibly other registered sources).

Target type: {target_type}
Target: {target}

Collected source results (JSON):
{json.dumps(results, indent=2, default=str)}

Rules:
- Do not invent facts. Only use what is present in the collected results.
- Clearly distinguish source-reported facts from your own inference.
- If a source failed or returned no data, treat that field as unknown —
  never assume "unknown" means safe.
- If sources conflict, acknowledge the conflict rather than picking one
  silently.
- Do not claim certainty when the evidence is incomplete or thin.
- Provide a concise overall assessment.
- {instructions}

Respond with ONLY a JSON object (no markdown fences, no extra text) with
exactly this shape:
{{
  "verdict": "SAFE | SUSPICIOUS | MALICIOUS | UNKNOWN",
  "confidence": "LOW | MEDIUM | HIGH",
  "summary": "Short explanation",
  "key_findings": ["Finding 1", "Finding 2"],
  "recommended_actions": ["Action 1", "Action 2"]
}}"""


def call_gemini(prompt: str) -> tuple[dict | None, str | None]:
    """Call Gemini and parse its JSON response. Returns (parsed, error)."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None, "Missing GEMINI_API_KEY environment variable."
    if genai is None:
        return None, "google-genai package is not installed."

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text = (response.text or "").strip()
        # Strip accidental markdown fences, just in case.
        text = re.sub(r"^```(json)?|```$", "", text, flags=re.MULTILINE).strip()
        parsed = json.loads(text)

        required_keys = {"verdict", "confidence", "summary", "key_findings", "recommended_actions"}
        if not required_keys.issubset(parsed.keys()):
            return None, "Gemini response was missing expected fields."

        return parsed, None

    except json.JSONDecodeError:
        return None, "Gemini returned a response that could not be parsed as JSON."
    except Exception as exc:  # noqa: BLE001 - surface any SDK/network error as a message
        return None, f"Gemini call failed: {exc}"


# --------------------------------------------------------------------------
# Display helpers
# --------------------------------------------------------------------------

VERDICT_STYLE = {
    "SAFE": ("🟢", "#1e7e34"),
    "SUSPICIOUS": ("🟡", "#b8860b"),
    "MALICIOUS": ("🔴", "#c0392b"),
    "UNKNOWN": ("⚪", "#6c757d"),
}


def render_verdict(insight: dict) -> None:
    verdict = str(insight.get("verdict", "UNKNOWN")).upper()
    confidence = str(insight.get("confidence", "LOW")).upper()
    emoji, color = VERDICT_STYLE.get(verdict, VERDICT_STYLE["UNKNOWN"])

    st.markdown(
        f"""
        <div style="border:1px solid {color}; border-radius:10px; padding:16px 20px; margin-bottom:12px;">
            <div style="font-size:1.4rem; font-weight:700; color:{color};">{emoji} Verdict: {verdict}</div>
            <div style="font-size:0.95rem; color:#555; margin-top:4px;">Confidence: {confidence.title()}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(
        "This is an assessment based on available intelligence, not a guarantee. "
        "An absence of detections does not prove something is safe."
    )


def render_ai_insight(insight: dict) -> None:
    st.subheader("AI Insight")
    st.markdown(f"**Summary**\n\n{insight.get('summary', 'No summary available.')}")

    findings = insight.get("key_findings") or []
    if findings:
        st.markdown("**Key Findings**")
        for item in findings:
            st.markdown(f"- {item}")

    actions = insight.get("recommended_actions") or []
    if actions:
        st.markdown("**Recommended Actions**")
        for item in actions:
            st.markdown(f"- {item}")


def render_source_results(results: dict[str, dict]) -> None:
    st.subheader("Source Results")
    for source_name, result in results.items():
        success = result.get("success")
        status_icon = "✅" if success else "⚠️"
        with st.expander(f"{status_icon} {source_name}"):
            if not success:
                st.error(result.get("error") or "This source failed with no additional details.")
                continue

            data = result.get("data") or {}
            if not data:
                st.info("No data returned.")
                continue

            for key, value in data.items():
                label = key.replace("_", " ").title()
                st.markdown(f"**{label}:** {value}")

            with st.expander("Raw data"):
                st.json(data)


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")

    st.title("ThreatLens")
    st.caption("Lightweight IP, domain, and URL threat analysis powered by VirusTotal, WHOIS, and Gemini.")

    missing_keys = [k for k in ("VIRUSTOTAL_API_KEY", "GEMINI_API_KEY") if not os.environ.get(k)]
    if missing_keys:
        st.warning(f"Missing environment variable(s): {', '.join(missing_keys)}. Related features will be limited.")

    with st.form("threatlens_form"):
        target_type = st.selectbox("Target type", ["IP Address", "Domain", "URL"])
        target = st.text_input(
            "Target",
            placeholder={
                "IP Address": "8.8.8.8",
                "Domain": "example.com",
                "URL": "https://example.com/login",
            }[target_type],
        )
        knowledge_level = st.radio("Knowledge level", ["Beginner", "Intermediate", "Expert"], horizontal=True)
        submitted = st.form_submit_button("Analyze")

    if not submitted:
        return

    is_valid, normalized_or_error = validate_target(target, target_type)
    if not is_valid:
        st.error(normalized_or_error)
        return

    normalized_target = normalized_or_error

    with st.spinner("Collecting intelligence from sources..."):
        results = collect_source_results(normalized_target, target_type)

    with st.spinner("Asking Gemini to interpret the results..."):
        prompt = build_gemini_prompt(normalized_target, target_type, knowledge_level, results)
        insight, gemini_error = call_gemini(prompt)

    st.divider()

    if insight:
        render_verdict(insight)
        render_ai_insight(insight)
    else:
        st.error(f"AI interpretation unavailable: {gemini_error}")
        st.info("Showing raw source results below.")

    st.divider()
    render_source_results(results)


if __name__ == "__main__":
    main()
