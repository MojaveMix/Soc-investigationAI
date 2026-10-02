import re
import ipaddress

class IOCExtractor:
    # Regular expressions for IOC extraction
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    URL_PATTERN = r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&\'\(\)\*\+,;=%]+'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|cc|xyz|top|biz|info|me|online|site|app|dev|pro|ai|co|eu|uk|de|nl|br|in|security|club)\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    CVE_PATTERN = r'\bCVE-\d{4}-\d{4,7}\b'
    MITRE_TECHNIQUE_PATTERN = r'\bT\d{4}(?:\.\d{3})?\b'
    REGISTRY_PATTERN = r'\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\\-]+\b'
    EMAIL_PATTERN = r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b'

    SUSPICIOUS_KEYWORDS = [
        "mimikatz", "vssadmin", "certutil", "powershell -enc", "invoke-expression",
        "iex", "downloadstring", "wevtutil cl", "rundll32", "cobalt strike", "meterpreter",
        "bloodhound", "sharphound", "rubeus", "psexec", "procdump", "chisel", "net user /add"
    ]

    @classmethod
    def is_private_ip(cls, ip_str):
        """Check if an IPv4 address belongs to private/loopback/bogon ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
        except ValueError:
            return False

    @classmethod
    def extract_all(cls, text):
        """Extract all potential IOCs and cybersecurity entities from raw text."""
        if not text:
            return []

        iocs = []
        seen = set()

        def add_ioc(ioc_type, value, threat_level="Suspicious", context=""):
            clean_val = value.strip().rstrip('.,;:)')
            key = (ioc_type, clean_val.lower())
            if key not in seen and clean_val:
                seen.add(key)
                iocs.append({
                    "type": ioc_type,
                    "value": clean_val,
                    "threat_level": threat_level,
                    "context": context
                })

        # 1. URLs
        urls = re.findall(cls.URL_PATTERN, text, re.IGNORECASE)
        for u in urls:
            add_ioc("URL", u, threat_level="Suspicious", context="Discovered in alert payload / network traffic")

        # 2. IPv4
        ips = re.findall(cls.IPV4_PATTERN, text)
        for ip in ips:
            # Skip common non-actionable IPs
            if ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4"):
                continue
            is_priv = cls.is_private_ip(ip)
            threat = "Contextual" if is_priv else "Suspicious"
            context = "Internal Network IP (RFC1918)" if is_priv else "Public/External Route IP"
            add_ioc("IPv4", ip, threat_level=threat, context=context)

        # 3. Domains
        domains = re.findall(cls.DOMAIN_PATTERN, text, re.IGNORECASE)
        common_legit = {"microsoft.com", "windows.com", "google.com", "github.com", "ubuntu.com"}
        for dom in domains:
            if dom.lower() in common_legit:
                continue
            add_ioc("Domain", dom, threat_level="Suspicious", context="External domain indicator")

        # 4. Hashes (order: SHA256 -> SHA1 -> MD5 to prevent sub-string overlap)
        sha256s = re.findall(cls.SHA256_PATTERN, text)
        for h in sha256s:
            add_ioc("Hash-SHA256", h, threat_level="Malicious", context="Cryptographic payload hash")

        sha1s = re.findall(cls.SHA1_PATTERN, text)
        for h in sha1s:
            if not any(h in s for s in sha256s):
                add_ioc("Hash-SHA1", h, threat_level="Malicious", context="Cryptographic payload hash")

        md5s = re.findall(cls.MD5_PATTERN, text)
        for h in md5s:
            if not any(h in s for s in sha256s) and not any(h in s for s in sha1s):
                add_ioc("Hash-MD5", h, threat_level="Malicious", context="Cryptographic payload hash")

        # 5. CVE Identifiers
        cves = re.findall(cls.CVE_PATTERN, text, re.IGNORECASE)
        for cve in cves:
            add_ioc("CVE", cve.upper(), threat_level="Critical", context="Explicit CVE vulnerability reference")

        # 6. MITRE Techniques
        mitres = re.findall(cls.MITRE_TECHNIQUE_PATTERN, text)
        for m in mitres:
            add_ioc("MITRE-ID", m.upper(), threat_level="Contextual", context="Direct ATT&CK Technique ID reference")

        # 7. Registry Keys
        registries = re.findall(cls.REGISTRY_PATTERN, text, re.IGNORECASE)
        for reg in registries:
            add_ioc("Registry Key", reg, threat_level="Suspicious", context="Windows registry modification/persistence path")

        # 8. Emails
        emails = re.findall(cls.EMAIL_PATTERN, text)
        for em in emails:
            add_ioc("Email", em, threat_level="Suspicious", context="Email address associated with alert")

        # 9. Suspicious Attack Strings / LOLBins
        lower_text = text.lower()
        for kw in cls.SUSPICIOUS_KEYWORDS:
            if kw in lower_text:
                add_ioc("Command / Tool", kw, threat_level="High Risk", context="Adversary execution artifact detected in text")

        return iocs
