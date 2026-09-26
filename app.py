import google.generativeai as genai
import streamlit as st
from sources import SOURCES, validate_target

# Configure Streamlit Page
st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")

st.title("ThreatLens")
st.markdown("Lightweight IP, domain, and URL threat analysis powered by VirusTotal, WHOIS, and Gemini.")

# Check for API keys in Streamlit secrets
vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
gemini_key = st.secrets.get("GEMINI_API_KEY", "")

if not vt_key or not gemini_key:
    st.warning("Missing environment variable(s): VIRUSTOTAL_API_KEY, GEMINI_API_KEY. Related features will be limited.")

if gemini_key:
    genai.configure(api_key=gemini_key)

# UI Controls: Pick target type, target input, and knowledge level
target_type = st.selectbox("Target type", ["IP Address", "Domain", "URL"])
target = st.text_input("Target", "8.8.8.8" if target_type == "IP Address" else "example.com")
knowledge_level = st.radio("Knowledge level", ["Beginner", "Intermediate", "Expert"], horizontal=True)

if st.button("Analyze"):
    if not validate_target(target_type, target):
        st.error(f"Invalid format entered for {target_type}. Please check your input.")
    else:
        with st.spinner("Collecting threat intel and consulting Gemini AI..."):
            # Step 1: Collect results using SOURCES registry
            results = {}
            for source_name, source_func in SOURCES.items():
                results[source_name] = source_func(target_type, target)
                
            # Step 2: Build a level-specific Gemini prompt
            ai_insight = "Gemini AI analysis unavailable due to missing API key."
            if gemini_key:
                try:
                    model = genai.GenerativeModel("gemini-2.5-flash")
                    prompt = f"""
                    You are a cybersecurity expert analyzing a {target_type} named '{target}'.
                    Here is the raw data collected from intelligence sources:
                    {results}

                    The user requested the explanation at a '{knowledge_level}' knowledge level.
                    
                    Provide:
                    1. A clear Verdict (Safe, Suspicious, or Malicious).
                    2. An insight explanation tailored strictly to a {knowledge_level} audience.
                    Keep it concise, professional, and actionable.
                    """
                    response = model.generate_content(prompt)
                    ai_insight = response.text
                except Exception as e:
                    ai_insight = f"Error generating AI insight: {str(e)}"
            
            # Step 3: Display Results and AI Insight Card
            st.markdown("---")
            st.subheader("Analysis Results")
            
            for s_name, s_data in results.items():
                with st.expander(f"Source: {s_name}"):
                    st.json(s_data)
            
            st.markdown("### 🤖 AI Insight & Verdict")
            
            # Color-coded verdict display based on AI output
            if "Malicious" in ai_insight:
                st.error(ai_insight)
            elif "Suspicious" in ai_insight:
                st.warning(ai_insight)
            else:
                st.success(ai_insight)
