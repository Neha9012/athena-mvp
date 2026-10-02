import os
from flask import Flask, jsonify
from flask_cors import CORS
from routes.api import api

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    app.config["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "athena123")  # demo credential
    origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")]
    CORS(app, origins=origins)
    app.register_blueprint(api)
    @app.errorhandler(404)
    def nf(_): return jsonify(error="Not found"), 404
    @app.errorhandler(500)
    def se(_): return jsonify(error="Internal server error"), 500
    return app

app = create_app()
if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG") == "1")
