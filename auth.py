import jwt
import datetime
import os
from functools import wraps
from flask import request, jsonify

JWT_SECRET = os.environ.get("JWT_SECRET", "asistencia-qr-secret-2026")
JWT_ALGO = "HS256"
JWT_EXP_HOURS = 8


def make_token(user_id: str, rol: str) -> str:
    payload = {
        "sub": user_id,
        "rol": rol,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXP_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])


def require_auth(*roles):
    """Decorator: @require_auth('admin') or @require_auth('maestro','admin')"""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Token requerido"}), 401
            token = auth[7:]
            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expirado"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token inválido"}), 401
            if roles and payload.get("rol") not in roles:
                return jsonify({"error": "Sin permiso"}), 403
            request.user_id = payload["sub"]
            request.user_rol = payload["rol"]
            return fn(*args, **kwargs)
        return wrapper
    return decorator
