import os
import sys
import logging
from flask import Flask, jsonify
from flask_cors import CORS
from config import Config
from models.database import db
from services.rag_service import rag_service

# Set up logging format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SecuRAG-Backend")

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable CORS for all routes (supports React frontend)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Initialize SQLAlchemy database
    try:
        db.init_app(app)
        with app.app_context():
            db.create_all()
            logger.info("Database tables verified in MariaDB/MySQL.")
    except Exception as e:
        logger.warning(f"Failed to connect to MariaDB at {config_class.SQLALCHEMY_DATABASE_URI}: {e}")
        # Graceful fallback to SQLite if MariaDB is unavailable
        fallback_db = f"sqlite:///{os.path.join(Config.BASE_DIR, 'data', 'securag_fallback.db')}"
        logger.info(f"Activating fallback database: {fallback_db}")
        app.config["SQLALCHEMY_DATABASE_URI"] = fallback_db
        with app.app_context():
            db.create_all()
            logger.info("SQLite fallback tables verified.")

    # Initialize and seed ChromaDB knowledge base
    try:
        with app.app_context():
            rag_service.initialize_and_seed()
    except Exception as e:
        logger.warning(f"ChromaDB seeding deferred: {e}")

    # Register Blueprints
    from routes.investigation_routes import investigation_bp
    from routes.ioc_routes import ioc_bp
    from routes.knowledge_routes import knowledge_bp
    from routes.system_routes import system_bp

    app.register_blueprint(investigation_bp)
    app.register_blueprint(ioc_bp)
    app.register_blueprint(knowledge_bp)
    app.register_blueprint(system_bp)

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db.session.remove()

    @app.route("/")
    def index():
        return jsonify({
            "platform": "SecuRAG AI",
            "version": "1.0.0",
            "description": "Local AI-powered cybersecurity investigation platform for SOC analysts",
            "endpoints": [
                "/api/health",
                "/api/investigations",
                "/api/ioc/extract",
                "/api/knowledge/search",
                "/api/presets"
            ]
        })

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", 5000))
    logger.info(f"SecuRAG AI Backend starting on http://127.0.0.1:{port} ...")
    app.run(host="0.0.0.0", port=port, debug=False)
