"""Flask Application Factory for Adaptive Security Gateway."""

import logging
import os
import torch
from flask import Flask, jsonify
from flask_cors import CORS
from gateway.config import Config
from gateway.routes.predict_routes import predict_bp
from gateway.routes.incident_routes import incident_bp
from gateway.routes.analytics_routes import analytics_bp
from gateway.services.db import get_db_status
from ml.inference import load_model, is_model_ready

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def create_app(config_class=Config) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable Cross-Origin Resource Sharing for dashboard
    CORS(app)

    # Attempt to load PyTorch model weights and vocab if present
    load_model(config_class.MODEL_PATH, config_class.VOCAB_PATH)

    # Register blueprints
    app.register_blueprint(predict_bp)
    app.register_blueprint(incident_bp)
    app.register_blueprint(analytics_bp)

    @app.route("/health", methods=["GET"])
    def health_check():
        cuda_status = torch.cuda.is_available()
        return jsonify({
            "status": "healthy",
            "service": "adaptive-security-gateway",
            "cuda_available": cuda_status,
            "device": torch.cuda.get_device_name(0) if cuda_status else "cpu",
            "vocab_loaded": os.path.exists(config_class.VOCAB_PATH),
            "model_loaded": is_model_ready(),
            "database": get_db_status()
        }), 200


    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"success": False, "data": None, "error": "Not Found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error("Internal Server Error: %s", error)
        return jsonify({"success": False, "data": None, "error": "Internal Server Error"}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=Config.PORT, debug=Config.DEBUG)
