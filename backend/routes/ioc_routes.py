from flask import Blueprint, request, jsonify
from models.database import db, IOCRecord
from services.ioc_extractor import IOCExtractor

ioc_bp = Blueprint("ioc", __name__, url_prefix="/api/ioc")

@ioc_bp.route("/extract", methods=["POST"])
def extract_iocs():
    """Fast regex-based IOC extraction from any arbitrary text."""
    data = request.get_json() or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "text is required"}), 400

    iocs = IOCExtractor.extract_all(text)
    return jsonify({
        "count": len(iocs),
        "iocs": iocs
    })

@ioc_bp.route("/list", methods=["GET"])
def list_recorded_iocs():
    """List all extracted IOCs across previous investigations."""
    try:
        ioc_type = request.args.get("type")
        threat_level = request.args.get("threat_level")
        search = request.args.get("search")
        limit = min(int(request.args.get("limit", 100)), 500)

        query = IOCRecord.query.order_by(IOCRecord.created_at.desc())

        if ioc_type and ioc_type.upper() != "ALL":
            query = query.filter(IOCRecord.ioc_type.ilike(f"%{ioc_type}%"))
        if threat_level and threat_level.upper() != "ALL":
            query = query.filter(IOCRecord.threat_level == threat_level)
        if search:
            query = query.filter(
                (IOCRecord.value.ilike(f"%{search}%")) |
                (IOCRecord.context.ilike(f"%{search}%"))
            )

        records = query.limit(limit).all()
        return jsonify({
            "total": len(records),
            "iocs": [r.to_dict() for r in records]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
