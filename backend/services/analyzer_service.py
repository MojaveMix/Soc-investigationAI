import json
import re
import logging
from config import Config
from models.database import db, Investigation, IOCRecord
from services.ollama_service import ollama_service
from services.rag_service import rag_service
from services.ioc_extractor import IOCExtractor

logger = logging.getLogger(__name__)

class AnalyzerService:
    def __init__(self):
        pass

    def run_investigation(self, raw_input, model=None, alert_type="Generic Security Alert", title=None):
        """
        End-to-end cybersecurity investigation workflow:
        1. Extract IOCs using heuristic regex engine.
        2. Query ChromaDB for relevant MITRE ATT&CK, OWASP, and CVE knowledge.
        3. Formulate SOC prompt with retrieved RAG context.
        4. Generate analysis using Ollama LLM.
        5. Parse response, normalize data, and persist to MariaDB.
        """
        chosen_model = model or Config.OLLAMA_MAIN_MODEL
        logger.info(f"Starting investigation with model [{chosen_model}]...")

        # Step 1: Extract IOCs from raw input
        extracted_iocs = IOCExtractor.extract_all(raw_input)
        logger.info(f"Extracted {len(extracted_iocs)} raw IOCs from input.")

        # Step 2: Query RAG for knowledge retrieval
        search_query = f"{raw_input[:600]} " + " ".join([f"{i['type']}:{i['value']}" for i in extracted_iocs[:6]])
        rag_docs = rag_service.search(query_text=search_query, top_k=4)
        rag_context = rag_service.format_context_for_prompt(rag_docs)
        logger.info(f"Retrieved {len(rag_docs)} knowledge chunks from ChromaDB.")

        # Step 3: Construct prompt
        system_prompt = (
            "You are SecuRAG AI, a Tier-3 Senior SOC Analyst and Threat Hunting Specialist. "
            "Your objective is to perform comprehensive cybersecurity investigations on security alerts, logs, and IOCs. "
            "You leverage MITRE ATT&CK, OWASP Top 10, and CVE intelligence to evaluate threats, calculate risk, "
            "and provide actionable remediation playbooks and threat hunting queries.\n\n"
            "CRITICAL: You must provide your final answer in valid JSON format matching the requested schema."
        )

        model_role_guidance = ""
        if "gemma" in chosen_model.lower():
            model_role_guidance = (
                "Provide an exceptionally thorough, forensic-grade incident report with a detailed attack chain timeline, "
                "adversary intentions, and deep architectural remediation."
            )
        elif "8b" in chosen_model:
            model_role_guidance = (
                "Provide a rapid, high-impact triage response focusing on critical containment actions and primary MITRE mapping."
            )
        else:
            model_role_guidance = (
                "Provide a balanced, highly rigorous SOC Tier-2/3 investigation report with precise MITRE mapping, "
                "risk scoring, IOC attribution, and defensive detection queries."
            )

        prompt = f"""### SECURITY INVESTIGATION REQUEST
Alert Type: {alert_type}
Investigation Custom Title: {title or 'Unspecified'}
Model Mode: {model_role_guidance}

### RAW SECURITY ALERT / LOG / IOC INPUT:
\"\"\"
{raw_input}
\"\"\"

### EXTRACTED IOC ARTIFACTS:
{json.dumps(extracted_iocs, indent=2)}

### RETRIEVED CYBERSECURITY INTELLIGENCE (MITRE ATT&CK / OWASP / CVE):
\"\"\"
{rag_context}
\"\"\"

### INSTRUCTIONS:
Analyze the provided event. Respond ONLY with a valid JSON object formatted EXACTLY as follows (no extraneous text before or after the JSON):

{{
  "title": "Clear, concise investigation title (e.g., 'Suspicious PowerShell Download Cradle & Ransomware Shadow Copy Deletion')",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
  "risk_score": 0 to 100 integer,
  "attack_stage": "e.g., Initial Access / Execution / Persistence / Defense Evasion / Credential Access / Lateral Movement / Impact",
  "summary": "2-4 sentence executive summary explaining what happened, the adversary technique, and immediate danger.",
  "mitre_techniques": [
    {{
      "id": "e.g., T1059.001",
      "name": "Technique Name",
      "tactic": "Tactic Name",
      "description": "Specific explanation of how this technique appears in the provided alert",
      "detection": "Recommended detection or telemetry logging rule"
    }}
  ],
  "iocs": [
    {{
      "type": "IPv4 / Domain / URL / Hash-SHA256 / CVE / Tool",
      "value": "indicator value",
      "threat_level": "Malicious" | "Suspicious" | "Contextual",
      "context": "Context or role of this IOC in the attack"
    }}
  ],
  "recommended_actions": {{
    "immediate_containment": [
      "Step 1: Specific containment action (e.g. isolate host IP 10.0.0.45)",
      "Step 2: Kill malicious process PID / block domain at DNS firewall"
    ],
    "eradication_remediation": [
      "Step 1: Rotate compromised credentials",
      "Step 2: Patch CVE or deploy GPO restriction"
    ],
    "hunting_queries": {{
      "kql": "Microsoft Sentinel / Defender KQL query to find similar activity",
      "splunk": "Splunk SPL query to hunt for this behavior",
      "sigma": "Sigma rule condition or logic"
    }}
  }},
  "full_report_markdown": "# Detailed Markdown Investigation Report\\n\\n### 1. Executive Summary\\n...\\n### 2. Attack Chain Timeline & Analysis\\n...\\n### 3. MITRE ATT&CK Mapping\\n...\\n### 4. Technical Indicators & Evidence\\n...\\n### 5. Recommended Defense & Containment\\n..."
}}
"""

        # Step 4: Dispatch to Ollama
        # Release any open database session from this thread while LLM is generating
        try:
            db.session.remove()
        except Exception:
            pass

        llm_result = ollama_service.generate_completion(
            prompt=prompt,
            model=chosen_model,
            system_prompt=system_prompt,
            temperature=0.1
        )

        if not llm_result.get("success"):
            logger.warning(f"Ollama generation failed: {llm_result.get('error')}. Creating fallback triage.")
            parsed_data = self._generate_heuristic_fallback(raw_input, extracted_iocs, rag_docs, alert_type, title, chosen_model)
        else:
            raw_response = llm_result.get("response", "")
            parsed_data = self._parse_llm_json(raw_response, raw_input, extracted_iocs, rag_docs, alert_type, title, chosen_model)

        # Step 5: Merge heuristic IOCs with LLM-detected IOCs
        all_iocs = self._merge_iocs(extracted_iocs, parsed_data.get("iocs", []))
        parsed_data["iocs"] = all_iocs

        # Step 6: Save to MariaDB
        investigation_record = self._save_to_database(parsed_data, raw_input, chosen_model, alert_type, title)

        return investigation_record.to_dict()

    def _parse_llm_json(self, response_text, raw_input, extracted_iocs, rag_docs, alert_type, title, model_name):
        """Robust parser to extract JSON from LLM output."""
        cleaned = response_text.strip()

        # Remove markdown code fences if present
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', cleaned, re.DOTALL)
        if json_match:
            cleaned = json_match.group(1).strip()
        elif cleaned.startswith("{") and cleaned.endswith("}"):
            pass
        else:
            # Try finding first { and last }
            first_brace = cleaned.find("{")
            last_brace = cleaned.rfind("}")
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                cleaned = cleaned[first_brace:last_brace + 1]

        try:
            data = json.loads(cleaned)
            # Ensure required fields exist
            if not data.get("title"):
                data["title"] = title or f"{alert_type} Investigation"
            if "risk_score" not in data:
                data["risk_score"] = 75
            if not data.get("severity"):
                data["severity"] = "HIGH"
            if not data.get("full_report_markdown"):
                data["full_report_markdown"] = response_text
            return data
        except Exception as e:
            logger.warning(f"JSON parsing failed on LLM response ({e}). Using heuristic extraction with full text.")
            return self._build_hybrid_from_text(response_text, raw_input, extracted_iocs, rag_docs, alert_type, title, model_name)

    def _build_hybrid_from_text(self, text, raw_input, extracted_iocs, rag_docs, alert_type, title, model_name):
        """Build structured response when LLM returns rich text instead of pure JSON."""
        # Calculate risk score based on IOCs and severity keywords
        text_lower = text.lower()
        severity = "MEDIUM"
        risk_score = 50

        if any(w in text_lower for w in ["critical", "ransomware", "cve-202", "zerologon", "log4shell", "shadow copy"]):
            severity = "CRITICAL"
            risk_score = 90
        elif any(w in text_lower for w in ["high", "mimikatz", "dump", "credential", "reverse shell", "lateral"]):
            severity = "HIGH"
            risk_score = 75
        elif any(w in text_lower for w in ["low", "info", "reconnaissance", "scan"]):
            severity = "LOW"
            risk_score = 30

        # Extract MITRE techniques from RAG docs
        mitre_list = []
        for doc in rag_docs:
            m = doc.get("metadata", {})
            if m.get("framework") == "MITRE ATT&CK":
                mitre_list.append({
                    "id": m.get("technique_id", "T1059"),
                    "name": m.get("name", "Execution"),
                    "tactic": m.get("category", "Execution"),
                    "description": "Correlated technique from cybersecurity knowledge base",
                    "detection": "Monitor process telemetry and event logs"
                })

        return {
            "title": title or f"Investigated Alert: {alert_type}",
            "severity": severity,
            "risk_score": risk_score,
            "attack_stage": "Active Threat Execution",
            "summary": text[:400].replace("\n", " ") + "...",
            "mitre_techniques": mitre_list,
            "iocs": extracted_iocs,
            "recommended_actions": {
                "immediate_containment": [
                    "Isolate affected endpoints from the corporate network.",
                    "Terminate suspicious processes and block communication with detected remote IPs."
                ],
                "eradication_remediation": [
                    "Perform credential resets for accounts associated with the compromised host.",
                    "Review recent Windows Event Logs (4688, 4104) and conduct an AV scan."
                ],
                "hunting_queries": {
                    "kql": f"SecurityEvent | where CommandLine has_any ('powershell', 'cmd.exe', 'vssadmin') | take 50",
                    "splunk": f"index=* (powershell OR cmd OR mimikatz) | stats count by host, user, CommandLine",
                    "sigma": "title: Suspicious Execution Pattern\nlogsource:\n  category: process_creation\ncondition: selection"
                }
            },
            "full_report_markdown": text if len(text) > 100 else f"## Investigation Report\n\n{text}"
        }

    def _generate_heuristic_fallback(self, raw_input, extracted_iocs, rag_docs, alert_type, title, model_name):
        """Fallback analysis when Ollama is offline or unreachable."""
        severity = "HIGH" if len(extracted_iocs) > 2 else "MEDIUM"
        risk_score = 70 if severity == "HIGH" else 45

        mitre_list = []
        for doc in rag_docs:
            m = doc.get("metadata", {})
            mitre_list.append({
                "id": m.get("technique_id", "T1059"),
                "name": m.get("name", "Suspicious Activity"),
                "tactic": m.get("category", "Execution"),
                "description": "Correlated from local cybersecurity vector knowledge base",
                "detection": "Review endpoint EDR and firewall logs"
            })

        summary = (
            f"Heuristic SOC alert analysis completed for '{alert_type}'. Detected {len(extracted_iocs)} "
            f"technical artifacts requiring immediate analyst review. Vector database matched {len(rag_docs)} "
            f"cybersecurity knowledge techniques."
        )

        report = f"""# SecuRAG AI Incident Investigation Report

**Incident Title:** {title or alert_type}
**Generated By:** Heuristic Vector Engine (Model: {model_name})
**Severity Assessment:** {severity} (Risk Score: {risk_score}/100)

---

### 1. Executive Summary
{summary}

### 2. Extracted Artifacts & Indicators
Found {len(extracted_iocs)} distinct indicators across the analyzed telemetry. See IOC section for exact values and recommended blocking actions.

### 3. MITRE ATT&CK & CVE Correlation
{rag_service.format_context_for_prompt(rag_docs)}

### 4. Recommended Next Steps
1. Review matched IOCs in perimeter firewall and EDR consoles.
2. Isolate involved endpoints if malicious execution is confirmed.
3. Validate domain account logins on affected hosts.
"""

        return {
            "title": title or f"Triage: {alert_type}",
            "severity": severity,
            "risk_score": risk_score,
            "attack_stage": "Triage & Identification",
            "summary": summary,
            "mitre_techniques": mitre_list,
            "iocs": extracted_iocs,
            "recommended_actions": {
                "immediate_containment": [
                    "Block all external IP and domain indicators at perimeter firewall / DNS.",
                    "Initiate host network containment on suspected asset."
                ],
                "eradication_remediation": [
                    "Perform memory and disk forensics on affected systems.",
                    "Audit privileged Active Directory logins."
                ],
                "hunting_queries": {
                    "kql": "DeviceProcessEvents | where ProcessCommandLine has_any ('powershell', 'cmd') | project Timestamp, DeviceName, FileName, ProcessCommandLine",
                    "splunk": "index=wineventlog EventCode=4688 | table _time host user CommandLine",
                    "sigma": "title: Suspicious Process Execution\nstatus: experimental"
                }
            },
            "full_report_markdown": report
        }

    def _merge_iocs(self, regex_iocs, llm_iocs):
        """Combine IOCs extracted by regex and LLM, avoiding duplicates."""
        merged = {}
        for item in regex_iocs:
            val = str(item.get("value", "")).strip().lower()
            if val:
                merged[val] = item

        for item in llm_iocs:
            val = str(item.get("value", "")).strip().lower()
            if val:
                if val in merged:
                    # Upgrade threat level if LLM tagged as malicious
                    if item.get("threat_level") == "Malicious":
                        merged[val]["threat_level"] = "Malicious"
                    if item.get("context"):
                        merged[val]["context"] = item["context"]
                else:
                    merged[val] = item

        return list(merged.values())

    def _save_to_database(self, data, raw_input, model_used, alert_type, custom_title):
        """Persist investigation and IOC records into MariaDB with reconnection resilience."""
        # Ensure any stale connection is closed and a fresh connection is checked out
        try:
            db.session.remove()
        except Exception:
            pass

        # Attempt to save with automatic retry on disconnect/OperationalError
        for attempt in range(2):
            try:
                inv = Investigation(
                    title=data.get("title") or custom_title or f"Alert Investigation ({alert_type})",
                    alert_type=alert_type or "Security Alert",
                    raw_input=raw_input,
                    model_used=model_used,
                    risk_score=int(data.get("risk_score", 50)),
                    severity=str(data.get("severity", "MEDIUM")).upper(),
                    summary=data.get("summary", ""),
                    attack_stage=data.get("attack_stage", "Unknown"),
                    mitre_techniques=data.get("mitre_techniques", []),
                    iocs_detected=data.get("iocs", []),
                    recommended_actions=data.get("recommended_actions", {}),
                    full_report_markdown=data.get("full_report_markdown", "")
                )
                db.session.add(inv)
                db.session.flush()  # to obtain inv.id

                # Save individual IOC records
                for ioc in data.get("iocs", []):
                    record = IOCRecord(
                        investigation_id=inv.id,
                        ioc_type=ioc.get("type", "Unknown"),
                        value=str(ioc.get("value", ""))[:500],
                        threat_level=ioc.get("threat_level", "Suspicious"),
                        context=ioc.get("context", "")
                    )
                    db.session.add(record)

                db.session.commit()
                logger.info(f"Successfully saved investigation #{inv.id} to MariaDB.")
                return inv
            except Exception as e:
                db.session.rollback()
                db.session.remove()
                logger.warning(f"Database save attempt {attempt + 1} encountered error: {e}")
                if attempt == 0:
                    # Clean up stale connection pool to force fresh socket connection
                    try:
                        db.engine.dispose()
                    except Exception:
                        pass
                else:
                    logger.error(f"Failed to save investigation to MariaDB after retry: {e}")
                    # Return safe in-memory representation so the analyst never loses the investigation report
                    class MockInvestigation:
                        def __init__(self, data, raw_input, model_used, alert_type, custom_title):
                            self.id = 0
                            self.title = data.get("title") or custom_title or f"Alert Investigation ({alert_type})"
                            self.alert_type = alert_type or "Security Alert"
                            self.raw_input = raw_input
                            self.model_used = model_used
                            self.risk_score = int(data.get("risk_score", 50))
                            self.severity = str(data.get("severity", "MEDIUM")).upper()
                            self.summary = data.get("summary", "")
                            self.attack_stage = data.get("attack_stage", "Unknown")
                            self.mitre_techniques = data.get("mitre_techniques", [])
                            self.iocs_detected = data.get("iocs", [])
                            self.recommended_actions = data.get("recommended_actions", {})
                            self.full_report_markdown = data.get("full_report_markdown", "")
                            from datetime import datetime, timezone
                            self.created_at = datetime.now(timezone.utc)

                        def to_dict(self):
                            return {
                                "id": self.id,
                                "title": self.title,
                                "alert_type": self.alert_type,
                                "raw_input": self.raw_input,
                                "model_used": self.model_used,
                                "risk_score": self.risk_score,
                                "severity": self.severity,
                                "summary": self.summary,
                                "attack_stage": self.attack_stage,
                                "mitre_techniques": self.mitre_techniques,
                                "iocs_detected": self.iocs_detected,
                                "recommended_actions": self.recommended_actions,
                                "full_report_markdown": self.full_report_markdown,
                                "created_at": self.created_at.isoformat(),
                                "ioc_count": len(self.iocs_detected),
                                "warning": "Database socket reset during generation; report rendered in-memory."
                            }

                    return MockInvestigation(data, raw_input, model_used, alert_type, custom_title)

analyzer_service = AnalyzerService()
