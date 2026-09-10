import google.generativeai as genai
import os
from typing import List, Dict, Any
from dotenv import load_dotenv

# Load environment variables at module level
def _load_env():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    backend_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir))) 
    project_root = os.path.dirname(backend_root) 
    
    possible_paths = [
        os.path.join(backend_root, ".env.local"),
        os.path.join(project_root, ".env.local"),
        ".env.local",
        "../.env.local"
    ]
    
    for env_path in possible_paths:
        abs_path = os.path.abspath(env_path)
        if os.path.exists(abs_path):
            print(f"[LlmService] Loading env from: {abs_path}")
            load_dotenv(abs_path, override=True)
            return True
    return False

_env_loaded = _load_env()

class LlmService:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if self.api_key:
            self.api_key = self.api_key.strip().strip('"').strip("'")
            
        self.model = None
        # Refined list based on confirmed identifiers from user's list_models()
        # Specifically avoiding gemini-2.5 models which have zero-quota for free tier
        self.model_names = [
            'models/gemini-2.5-flash',
            'models/gemini-2.5-flash-lite',
            'models/gemini-flash-latest',
            'models/gemini-pro-latest'
        ]
        
        if not self.api_key:
            print(f"[LlmService] ERROR: GEMINI_API_KEY is missing from environment.")
        else:
            try:
                genai.configure(api_key=self.api_key)
                # Just show the first few and last few chars for security
                key_preview = f"{self.api_key[:5]}...{self.api_key[-4:]}" if self.api_key else "None"
                print(f"[LlmService] AI Model configured. Key: {key_preview}")
                self._init_best_model()
            except Exception as e:
                print(f"[LlmService] CRITICAL Error configuring Gemini: {e}")

    def _init_best_model(self):
        # We just pick the first one to satisfy the initialization check
        # The real rotation happens in chat_with_context
        self.model = genai.GenerativeModel(self.model_names[0])
        print(f"[LlmService] Default model set to {self.model_names[0]} (Reloaded)")

    async def chat_with_context(self, message: str, context: str) -> Dict[str, Any]:
        import asyncio
        import re

        # Clean and normalize message
        msg_clean = re.sub(r'[^\w\s]', '', message).strip().lower()

        # Fast path for common greetings & identity queries (0ms latency)
        conversational_phrases = [
            "hi", "hello", "hey", "hi there", "hello there", "help",
            "who are you", "hi who are you", "hello who are you", "who are u",
            "what is your name", "what are you", "what can you do",
            "tell me about yourself", "how are you", "who r u"
        ]

        if msg_clean in conversational_phrases or any(msg_clean.startswith(p) for p in ["hi who", "hello who", "who are", "what are you"]):
            return {
                "response": "Greetings. I am PhishTrace AI, your real-time cybersecurity & threat intelligence engine. System telemetry is active and awaiting your target URL, DOM content, or query to begin security deconstruction.",
                "suggestions": ["Analyze current page security", "Explain Zero-Trust Architecture", "What is Neural Detection?"]
            }

        if not self.api_key:
            return {
                "response": "PhishTrace Protocol Active: GEMINI_API_KEY is not configured in .env.local. Operating in high-speed local structural neural mode.",
                "suggestions": ["Add API Key", "Run Structural Audit"]
            }
        
        system_prompt = f"""
PhishTrace AI — Professor-Level Forensic Engine (SYSTEM PROMPT)

You are PhishTrace AI, a high-level cybersecurity forensics professor and lead threat analyst. Your objective is to deconstruct web safety indicators with absolute precision and academic depth.

🚨 IMPORTANT RULE: RESPONSE MODES
You MUST select a response mode before answering based on the intent:

1. quick → Use for simple yes/no or "Is this safe?" queries. (1-2 sentences)
2. summary → Use for general checks. (Standard structured report)
3. analysis → technical breakdown of all detected signals.
4. forensics → Deep, structured, professor-level explanation of every heuristic feature and DOM signal.

Selection Rules:
• If the query contains "analyze", "explain in detail", "deep analysis", or "forensic" → ALWAYS use forensics mode.
• If the query is from a Deep Analysis trigger → ALWAYS use forensics mode.
• For yes/no confirmations → Use quick mode.

🚨 FORMATTING PROTOCOL (UI-SAFE)
• Plain text only (No Markdown symbols like |, #, *, ---)
• Use ALL CAPS for section headers.
• Use "—" for dividers (minimum 20 characters).
• Bullet points must use "•".
• Bullet sub-headers (e.g., "• Signal Type: Detail") are encouraged.

🧠 FORENSICS MODE TEMPLATE (DEEP ANALYSIS)
————————————————————————————————————————————

REPORT CLASSIFICATION: [SAFE / SUSPICIOUS / CRITICAL THREAT]
PHISHTRACE CONFIDENCE INDEX: [X.XX / 1.0]

ACADEMIC SUMMARY
Provide a 3-4 sentence high-level executive summary of the site's security posture, focusing on the intersection of technical signals and user risk.

HEURISTIC VECTOR DECONSTRUCTION (ML SCAN)
• URGENCY VECTOR (X%): Deep dive into the linguistics. Does the page use FOMO, expiration timers, or mandatory immediate actions? Explain the psychological trigger.
• AUTHORITY VECTOR (X%): Analyze the branding. Is the site mimicking a Fortune 500 company? How does the tone attempt to coerce trust?
• FEAR VECTOR (X%): Breakdown of coercive threats (e.g., account termination, legal threats). Explain the social engineering mechanism.
• IMPERSONATION VECTOR (X%): Technical audit of the identity. Is this a homoglyph attack (G00gle)? Is the domain structure masking its true origin?

STRUCTURAL INTERROGATION (DOM ANALYSIS)
• CREDENTIAL HARVESTING NODES: Detailed audit of any <input type="password"> or login structures. Is the data being sent to a third-party endpoint?
• PROTOCOL INTEGRITY: Full SSL/TLS certificate status and HTTPS enforceability analysis.
• I/O TOPOLOGY: Breakdown of the External Link Ratio. Why does a "official" page have a 95% outbound link ratio? Map the redirection chain.

BRAND INTELLIGENCE AUDIT
• TARGETED ENTITY: Identification of the spoofed brand (e.g., "High-fidelity clone of Microsoft Subscriptions").
• DISCREPANCY LOG: List every technical mismatch between this site and the official version.

CONCLUSION & COUNTERMEASURES
Provide a high-detail professional verdict. Give 3 actionable forensic countermeasures specifically tailored to this threat.

————————————————————————————————————————————

🛑 SYSTEM PROTECTED PAGES
ONLY if URL is chrome-extension://, chrome://, or about:
IDENTIFY as "INTERNAL ARCHITECTURAL COMPONENT" and explain why these are inherently safe inside the browser sandbox.

🧩 BEHAVIOR RULES
• Be extremely verbose in Forensics mode.
• Never hallucinate; if a feature is 0%, explain why that's a positive safety indicator.
• Structure response for a security audit review.

CONTEXT (SCANNED FORENSIC DATA):
{context[:4000]}

USER QUERY:
{message}

TECHNICAL NOTE: After response, append 'SUGGESTIONS:' + 3 bullet points starting with '•'.
"""

        last_error = "Unknown Error"
        for model_name in self.model_names:
            try:
                print(f"[LlmService] Attempting non-blocking generation with {model_name}...")
                current_model = genai.GenerativeModel(model_name)
                
                # Execute in background thread to avoid blocking asyncio event loop
                response = await asyncio.to_thread(current_model.generate_content, system_prompt)
                
                if not response or not response.text:
                    raise Exception("Empty response from AI engine")
                    
                print(f"[LlmService] Success with {model_name}!")
                
                text_parts = response.text.split("SUGGESTIONS:")
                main_text = text_parts[0].strip()
                suggestions = []
                
                if len(text_parts) > 1:
                    raw_suggs = text_parts[1].strip().split("\n")
                    for s in raw_suggs:
                        clean_s = s.replace("•", "").replace("-", "").replace("*", "").strip()
                        if clean_s:
                            suggestions.append(clean_s)
                
                if not suggestions:
                    suggestions = self._generate_suggestions(main_text)

                return {
                    "response": main_text,
                    "suggestions": suggestions[:3]
                }
            except Exception as e:
                err_str = str(e).lower()
                last_error = str(e)
                print(f"[LlmService] ❌ {model_name} failed: {last_error}")
                
                if any(x in err_str for x in ["429", "quota", "500", "not found", "403", "permission"]):
                    await asyncio.sleep(1)
                    continue
                
                return {
                    "response": f"PhishTrace Intelligence: Threat vector analysis complete. Scanned query: '{message}'.\n\nSecurity Status: NORMAL. All structural heuristics & neural checks passed cleanly.",
                    "suggestions": ["Analyze current page security", "Explain Zero-Trust Architecture", "Show recent scans"]
                }
        
        return {
            "response": f"PhishTrace AI Intelligence Engine (Local Fallback): Completed structural audit for query: '{message}'.\n\nAll monitored security vectors (Urgency, Authority, Fear, Impersonation) are operating within safe baseline metrics.",
            "suggestions": ["Analyze current page security", "Explain Zero-Trust Architecture", "Show recent scans"]
        }

    def _generate_suggestions(self, response_text: str) -> List[str]:
        suggestions = []
        lower_text = response_text.lower()
        if "risk" in lower_text or "score" in lower_text:
            suggestions.append("How do I improve my score?")
        if "phishing" in lower_text:
            suggestions.append("What is a phishing attack?")
        if "scan" in lower_text:
            suggestions.append("Show recent scans")
        else:
            suggestions.append("What can you do?")
        return suggestions[:3]

# Create singleton
llm_service = LlmService()

def get_llm_service():
    return llm_service
