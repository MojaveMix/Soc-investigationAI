from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON, Text, String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship

db = SQLAlchemy()

class Investigation(db.Model):
    __tablename__ = "investigations"

    id = db.Column(Integer, primary_key=True, autoincrement=True)
    title = db.Column(String(255), nullable=False)
    alert_type = db.Column(String(100), default="Generic Security Alert")
    raw_input = db.Column(Text, nullable=False)
    model_used = db.Column(String(100), default="qwen3.5:9b")
    risk_score = db.Column(Integer, default=50)
    severity = db.Column(String(50), default="MEDIUM")
    summary = db.Column(Text, nullable=True)
    attack_stage = db.Column(String(100), default="Unknown")
    
    # Structured cybersecurity data stored as JSON
    mitre_techniques = db.Column(JSON, default=list)
    iocs_detected = db.Column(JSON, default=list)
    recommended_actions = db.Column(JSON, default=dict)
    
    # Comprehensive forensic investigation report
    full_report_markdown = db.Column(Text, nullable=True)
    
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to IOC records
    ioc_records = relationship("IOCRecord", backref="investigation", cascade="all, delete-orphan", lazy=True)

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
            "mitre_techniques": self.mitre_techniques or [],
            "iocs_detected": self.iocs_detected or [],
            "recommended_actions": self.recommended_actions or {},
            "full_report_markdown": self.full_report_markdown or "",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "ioc_count": len(self.iocs_detected or [])
        }


class IOCRecord(db.Model):
    __tablename__ = "ioc_records"

    id = db.Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = db.Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True)
    ioc_type = db.Column(String(50), nullable=False)  # IP, Domain, URL, Hash-MD5, Hash-SHA256, CVE, Registry, Command
    value = db.Column(String(500), nullable=False, index=True)
    threat_level = db.Column(String(50), default="Suspicious")  # Malicious, Suspicious, Contextual, Benign
    context = db.Column(Text, nullable=True)
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "threat_level": self.threat_level,
            "context": self.context,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class KnowledgeDocument(db.Model):
    __tablename__ = "knowledge_documents"

    id = db.Column(Integer, primary_key=True, autoincrement=True)
    framework = db.Column(String(50), nullable=False)  # MITRE ATT&CK, OWASP Top 10, CVE
    technique_id = db.Column(String(100), nullable=False, index=True)  # e.g., T1059.001, OWASP-A03, CVE-2021-44228
    name = db.Column(String(255), nullable=False)
    category = db.Column(String(100), nullable=True)  # Tactic or Category
    description = db.Column(Text, nullable=False)
    detection_remediation = db.Column(Text, nullable=True)
    chroma_id = db.Column(String(100), nullable=True)
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "framework": self.framework,
            "technique_id": self.technique_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "detection_remediation": self.detection_remediation,
            "chroma_id": self.chroma_id,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
