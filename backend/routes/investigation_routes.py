import logging
from flask import Blueprint, request, jsonify
from models.database import db, Investigation, IOCRecord
from services.analyzer_service import analyzer_service

logger = logging.getLogger(__name__)
investigation_bp = Blueprint("investigation", __name__, url_prefix="/api/investigations")

@investigation_bp.route("", methods=["POST"])
@investigation_bp.route("/run", methods=["POST"])
def run_investigation():
    """Trigger an AI-driven cybersecurity investigation."""
    try:
        data = request.get_json() or {}
        raw_input = data.get("raw_input", "").strip()
        if not raw_input:
            return jsonify({"error": "raw_input is required (security alert, log, or IOC text)"}), 400

        model = data.get("model")
        alert_type = data.get("alert_type", "Generic Security Alert")
        title = data.get("title")

        result = analyzer_service.run_investigation(
            raw_input=raw_input,
            model=model,
            alert_type=alert_type,
            title=title
        )
        return jsonify({"success": True, "investigation": result}), 201
    except Exception as e:
        logger.error(f"Investigation execution error: {e}", exc_info=True)
        return jsonify({"error": f"Investigation failed: {str(e)}"}), 500


@investigation_bp.route("/upload", methods=["POST"])
def upload_and_investigate():
    """Upload a log file (.log, .txt, .json, .csv, .xml) and investigate."""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded in 'file' form field."}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "Empty filename."}), 400

        # Read file bytes and decode text
        content_bytes = file.read()
        raw_text = ""
        for encoding in ["utf-8", "latin-1", "utf-16", "cp1252"]:
            try:
                raw_text = content_bytes.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        if not raw_text.strip():
            return jsonify({"error": "Unable to decode text from uploaded log file or file is empty."}), 400

        model = request.form.get("model")
        alert_type = request.form.get("alert_type") or f"Log File: {file.filename}"
        title = request.form.get("title") or f"Log Investigation: {file.filename}"

        # If file is very large (> 200KB), take first 1500 lines or sample high-priority lines
        if len(raw_text) > 200000:
            lines = raw_text.splitlines()
            sampled = lines[:1500]
            raw_text = "\n".join(sampled) + f"\n\n[... Truncated for AI analysis. Total file lines: {len(lines)} ...]"

        result = analyzer_service.run_investigation(
            raw_input=raw_text,
            model=model,
            alert_type=alert_type,
            title=title
        )
        return jsonify({
            "success": True, 
            "filename": file.filename,
            "bytes_read": len(content_bytes),
            "investigation": result
        }), 201
    except Exception as e:
        logger.error(f"File upload investigation error: {e}", exc_info=True)
        return jsonify({"error": f"Upload investigation failed: {str(e)}"}), 500


@investigation_bp.route("", methods=["GET"])
def list_investigations():
    """Retrieve list of past investigations with optional filtering."""
    try:
        severity = request.args.get("severity")
        model = request.args.get("model")
        search = request.args.get("search")
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = int(request.args.get("offset", 0))

        query = Investigation.query.order_by(Investigation.created_at.desc())

        if severity and severity.upper() != "ALL":
            query = query.filter(Investigation.severity == severity.upper())
        if model and model.lower() != "all":
            query = query.filter(Investigation.model_used.ilike(f"%{model}%"))
        if search:
            query = query.filter(
                (Investigation.title.ilike(f"%{search}%")) |
                (Investigation.summary.ilike(f"%{search}%")) |
                (Investigation.raw_input.ilike(f"%{search}%"))
            )

        total = query.count()
        items = query.offset(offset).limit(limit).all()

        return jsonify({
            "total": total,
            "limit": limit,
            "offset": offset,
            "investigations": [i.to_dict() for i in items]
        })
    except Exception as e:
        logger.error(f"Error fetching investigations: {e}")
        return jsonify({"error": str(e)}), 500


@investigation_bp.route("/<int:inv_id>", methods=["GET"])
def get_investigation(inv_id):
    """Get single investigation by ID."""
    try:
        inv = Investigation.query.get(inv_id)
        if not inv:
            return jsonify({"error": f"Investigation #{inv_id} not found"}), 404
        return jsonify(inv.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@investigation_bp.route("/<int:inv_id>", methods=["DELETE"])
def delete_investigation(inv_id):
    """Delete an investigation by ID."""
    try:
        inv = Investigation.query.get(inv_id)
        if not inv:
            return jsonify({"error": f"Investigation #{inv_id} not found"}), 404
        db.session.delete(inv)
        db.session.commit()
        return jsonify({"success": True, "message": f"Investigation #{inv_id} deleted."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@investigation_bp.route("/<int:inv_id>/reanalyze", methods=["POST"])
def reanalyze_investigation(inv_id):
    """Re-run analysis on an existing investigation with a new or deeper model."""
    try:
        inv = Investigation.query.get(inv_id)
        if not inv:
            return jsonify({"error": f"Investigation #{inv_id} not found"}), 404

        data = request.get_json() or {}
        new_model = data.get("model")

        result = analyzer_service.run_investigation(
            raw_input=inv.raw_input,
            model=new_model,
            alert_type=inv.alert_type,
            title=f"{inv.title} (Reanalyzed)"
        )
        return jsonify({"success": True, "investigation": result}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
