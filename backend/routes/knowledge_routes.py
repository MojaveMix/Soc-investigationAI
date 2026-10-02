import logging
from flask import Blueprint, request, jsonify
from services.rag_service import rag_service
from services.knowledge_seed import CYBERSECURITY_KNOWLEDGE_SEED

logger = logging.getLogger(__name__)
knowledge_bp = Blueprint("knowledge", __name__, url_prefix="/api/knowledge")

@knowledge_bp.route("/search", methods=["GET", "POST"])
def search_knowledge():
    """Query the ChromaDB RAG knowledge base."""
    if request.method == "POST":
        data = request.get_json() or {}
        query = data.get("query", "").strip()
        framework = data.get("framework")
        top_k = int(data.get("top_k", 5))
    else:
        query = request.args.get("query", "").strip()
        framework = request.args.get("framework")
        top_k = int(request.args.get("top_k", 5))

    if not query:
        # If no query provided, return sample/all seed records
        results = [
            {
                "id": f"seed_{item['technique_id']}",
                "content": f"[{item['framework']}] {item['technique_id']} - {item['name']}\nDescription: {item['description']}",
                "metadata": item,
                "similarity_score": 1.0
            }
            for item in CYBERSECURITY_KNOWLEDGE_SEED
            if not framework or item.get("framework") == framework
        ]
        return jsonify({"query": "", "results": results[:top_k], "total": len(results)})

    results = rag_service.search(query_text=query, top_k=top_k, framework_filter=framework)
    return jsonify({
        "query": query,
        "framework": framework,
        "results": results,
        "count": len(results)
    })

@knowledge_bp.route("/stats", methods=["GET"])
def knowledge_stats():
    """Get vector database and knowledge framework statistics."""
    stats = rag_service.get_stats()
    return jsonify(stats)

@knowledge_bp.route("/reindex", methods=["POST"])
def reindex_knowledge():
    """Force re-indexing of seed knowledge into ChromaDB."""
    result = rag_service.initialize_and_seed(force=True)
    return jsonify(result)

@knowledge_bp.route("/custom", methods=["POST"])
def add_custom():
    """Add a custom threat intel entry or SOC playbook."""
    data = request.get_json() or {}
    framework = data.get("framework", "Custom Playbook")
    technique_id = data.get("technique_id", "CUSTOM-01")
    name = data.get("name", "Custom Rule")
    category = data.get("category", "Internal SOC")
    description = data.get("description", "")
    detection_remediation = data.get("detection_remediation", "")

    if not description:
        return jsonify({"error": "description is required"}), 400

    doc_id = rag_service.add_custom_document(
        framework=framework,
        technique_id=technique_id,
        name=name,
        category=category,
        description=description,
        detection_remediation=detection_remediation
    )
    return jsonify({"success": True, "doc_id": doc_id}), 201
