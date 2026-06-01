import uuid
import hashlib
import math
import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db, init_db
from auth import make_token, require_auth

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

QR_SECRET = "asistencia-qr-mobile-2026"
QR_REFRESH_SECONDS = 20


# ─── helpers ────────────────────────────────────────────────────────────────

def new_id():
    return str(uuid.uuid4())


def today_str():
    return datetime.date.today().isoformat()


def hash_string(text: str) -> str:
    val = 0
    for ch in text:
        val = ((val * 31) + ord(ch)) & 0xFFFFFFFF
    return format(val, "08x")


def current_slot() -> int:
    import time
    return math.floor(time.time() / QR_REFRESH_SECONDS)


def build_qr_token(alumno_id: str, clase_id: str, fecha: str, slot: int) -> str:
    sig = hash_string(f"{alumno_id}|{clase_id}|{fecha}|{slot}|{QR_SECRET}")
    return f"asisqr:{alumno_id}:{clase_id}:{fecha}:{slot}:{sig}"


def validate_qr_token(token: str, clase_id: str) -> tuple[bool, str]:
    parts = token.strip().split(":")
    if len(parts) != 6 or parts[0] != "asisqr":
        return False, "Formato de QR inválido"

    _, alumno_id, cls_id, fecha, slot_str, signature = parts

    if cls_id != clase_id:
        return False, "El QR pertenece a otra clase"
    if fecha != today_str():
        return False, "El QR no corresponde a la fecha actual"

    try:
        slot = int(slot_str)
    except ValueError:
        return False, "Ventana de tiempo inválida"

    expected_sig = hash_string(f"{alumno_id}|{cls_id}|{fecha}|{slot}|{QR_SECRET}")
    if expected_sig != signature:
        return False, "Firma del QR inválida (posible manipulación)"

    active = current_slot()
    if slot < active - 1 or slot > active:
        return False, "QR expirado (más de 40 segundos)"

    return True, alumno_id


# ─── auth ────────────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
def login():
    data = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña requeridos"}), 400

    db = get_db()
    user = db.execute(
        "SELECT * FROM usuarios WHERE username = ?", (username,)
    ).fetchone()
    db.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    token = make_token(user["id"], user["rol"])
    return jsonify({
        "token": token,
        "user": {
            "id": user["id"],
            "nombre": user["nombre"],
            "username": user["username"],
            "rol": user["rol"],
            "matricula": user["matricula"],
        }
    })


@app.get("/api/auth/me")
@require_auth("admin", "maestro", "alumno")
def me():
    db = get_db()
    user = db.execute(
        "SELECT id, nombre, username, rol, matricula FROM usuarios WHERE id=?",
        (request.user_id,)
    ).fetchone()
    db.close()
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    return jsonify(dict(user))


# ─── admin: usuarios ─────────────────────────────────────────────────────────

@app.get("/api/admin/usuarios")
@require_auth("admin")
def list_usuarios():
    rol = request.args.get("rol")
    db = get_db()
    if rol:
        rows = db.execute(
            "SELECT id, nombre, username, rol, matricula, created_at FROM usuarios WHERE rol=? ORDER BY nombre",
            (rol,)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id, nombre, username, rol, matricula, created_at FROM usuarios ORDER BY rol, nombre"
        ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.post("/api/admin/usuarios")
@require_auth("admin")
def create_usuario():
    data = request.get_json()
    nombre = (data.get("nombre") or "").strip()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    rol = data.get("rol")
    matricula = (data.get("matricula") or "").strip() or None

    if not nombre or not username or not password or rol not in ("maestro", "alumno", "admin"):
        return jsonify({"error": "Datos incompletos o rol inválido"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM usuarios WHERE username=?", (username,)).fetchone()
    if existing:
        db.close()
        return jsonify({"error": "El nombre de usuario ya existe"}), 409

    uid = new_id()
    db.execute(
        "INSERT INTO usuarios (id, nombre, username, password, rol, matricula) VALUES (?,?,?,?,?,?)",
        (uid, nombre, username, generate_password_hash(password), rol, matricula)
    )
    db.commit()
    db.close()
    return jsonify({"id": uid, "nombre": nombre, "username": username, "rol": rol, "matricula": matricula}), 201


@app.delete("/api/admin/usuarios/<uid>")
@require_auth("admin")
def delete_usuario(uid):
    db = get_db()
    db.execute("DELETE FROM usuarios WHERE id=?", (uid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.put("/api/admin/usuarios/<uid>")
@require_auth("admin")
def update_usuario(uid):
    data = request.get_json()
    db = get_db()
    user = db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone()
    if not user:
        db.close()
        return jsonify({"error": "No encontrado"}), 404

    nombre = (data.get("nombre") or user["nombre"]).strip()
    matricula = data.get("matricula", user["matricula"])
    new_password = (data.get("password") or "").strip()

    if new_password:
        db.execute(
            "UPDATE usuarios SET nombre=?, matricula=?, password=? WHERE id=?",
            (nombre, matricula, generate_password_hash(new_password), uid)
        )
    else:
        db.execute(
            "UPDATE usuarios SET nombre=?, matricula=? WHERE id=?",
            (nombre, matricula, uid)
        )
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ─── admin: clases ───────────────────────────────────────────────────────────

@app.get("/api/admin/clases")
@require_auth("admin")
def admin_list_clases():
    db = get_db()
    rows = db.execute("""
        SELECT c.*, u.nombre as maestro_nombre
        FROM clases c
        JOIN usuarios u ON u.id = c.maestro_id
        ORDER BY c.nombre
    """).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.post("/api/admin/clases")
@require_auth("admin")
def create_clase():
    data = request.get_json()
    nombre = (data.get("nombre") or "").strip()
    grupo = (data.get("grupo") or "").strip()
    horario = (data.get("horario") or "").strip()
    salon = (data.get("salon") or "").strip()
    maestro_id = data.get("maestro_id")

    if not nombre or not grupo or not horario or not salon or not maestro_id:
        return jsonify({"error": "Todos los campos son requeridos"}), 400

    db = get_db()
    maestro = db.execute(
        "SELECT id FROM usuarios WHERE id=? AND rol='maestro'", (maestro_id,)
    ).fetchone()
    if not maestro:
        db.close()
        return jsonify({"error": "Maestro no válido"}), 400

    cid = new_id()
    db.execute(
        "INSERT INTO clases (id, nombre, grupo, horario, salon, maestro_id) VALUES (?,?,?,?,?,?)",
        (cid, nombre, grupo, horario, salon, maestro_id)
    )
    db.commit()
    db.close()
    return jsonify({"id": cid, "nombre": nombre, "grupo": grupo}), 201


@app.delete("/api/admin/clases/<cid>")
@require_auth("admin")
def delete_clase(cid):
    db = get_db()
    db.execute("DELETE FROM clases WHERE id=?", (cid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ─── admin: inscripciones ─────────────────────────────────────────────────────

@app.get("/api/admin/clases/<cid>/alumnos")
@require_auth("admin")
def list_inscritos(cid):
    db = get_db()
    rows = db.execute("""
        SELECT u.id, u.nombre, u.username, u.matricula
        FROM inscripciones i
        JOIN usuarios u ON u.id = i.alumno_id
        WHERE i.clase_id = ?
        ORDER BY u.nombre
    """, (cid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.post("/api/admin/clases/<cid>/alumnos")
@require_auth("admin")
def inscribir_alumno(cid):
    data = request.get_json()
    alumno_id = data.get("alumno_id")
    if not alumno_id:
        return jsonify({"error": "alumno_id requerido"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO inscripciones (id, alumno_id, clase_id) VALUES (?,?,?)",
            (new_id(), alumno_id, cid)
        )
        db.commit()
    except Exception:
        db.close()
        return jsonify({"error": "El alumno ya está inscrito"}), 409
    db.close()
    return jsonify({"ok": True}), 201


@app.delete("/api/admin/clases/<cid>/alumnos/<aid>")
@require_auth("admin")
def desinscribir_alumno(cid, aid):
    db = get_db()
    db.execute(
        "DELETE FROM inscripciones WHERE clase_id=? AND alumno_id=?", (cid, aid)
    )
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ─── maestro ─────────────────────────────────────────────────────────────────

@app.get("/api/maestro/clases")
@require_auth("maestro")
def maestro_clases():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM clases WHERE maestro_id=? ORDER BY nombre",
        (request.user_id,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.get("/api/maestro/clases/<cid>/alumnos")
@require_auth("maestro")
def maestro_alumnos(cid):
    db = get_db()
    # Verify class belongs to this teacher
    clase = db.execute(
        "SELECT id FROM clases WHERE id=? AND maestro_id=?", (cid, request.user_id)
    ).fetchone()
    if not clase:
        db.close()
        return jsonify({"error": "Clase no encontrada"}), 404

    rows = db.execute("""
        SELECT u.id, u.nombre, u.username, u.matricula
        FROM inscripciones i
        JOIN usuarios u ON u.id = i.alumno_id
        WHERE i.clase_id = ?
        ORDER BY u.nombre
    """, (cid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.get("/api/maestro/clases/<cid>/asistencias")
@require_auth("maestro")
def maestro_asistencias(cid):
    fecha = request.args.get("fecha", today_str())
    db = get_db()
    rows = db.execute(
        "SELECT * FROM asistencias WHERE clase_id=? AND fecha=?",
        (cid, fecha)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.get("/api/maestro/clases/<cid>/asistencias/historico")
@require_auth("maestro")
def maestro_historico(cid):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM asistencias WHERE clase_id=? ORDER BY fecha DESC, scanned_at DESC",
        (cid,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.post("/api/maestro/clases/<cid>/escanear")
@require_auth("maestro")
def escanear_qr(cid):
    data = request.get_json()
    token = data.get("token", "")

    # Verify class belongs to teacher
    db = get_db()
    clase = db.execute(
        "SELECT * FROM clases WHERE id=? AND maestro_id=?", (cid, request.user_id)
    ).fetchone()
    if not clase:
        db.close()
        return jsonify({"error": "Clase no encontrada"}), 404

    valid, result = validate_qr_token(token, cid)
    if not valid:
        db.close()
        return jsonify({"error": result}), 400

    alumno_id = result

    # Check student is enrolled
    inscrito = db.execute(
        "SELECT id FROM inscripciones WHERE alumno_id=? AND clase_id=?",
        (alumno_id, cid)
    ).fetchone()
    if not inscrito:
        db.close()
        return jsonify({"error": "El alumno no está inscrito en esta clase"}), 400

    alumno = db.execute(
        "SELECT nombre FROM usuarios WHERE id=?", (alumno_id,)
    ).fetchone()

    fecha = today_str()
    now_iso = datetime.datetime.now().isoformat()
    record_id = f"{cid}-{alumno_id}-{fecha}"

    existing = db.execute(
        "SELECT * FROM asistencias WHERE id=?", (record_id,)
    ).fetchone()

    if existing:
        db.execute(
            "UPDATE asistencias SET estado='presente', scanned_at=? WHERE id=?",
            (now_iso, record_id)
        )
    else:
        db.execute(
            "INSERT INTO asistencias (id, clase_id, alumno_id, fecha, estado, scanned_at) VALUES (?,?,?,?,?,?)",
            (record_id, cid, alumno_id, fecha, "presente", now_iso)
        )

    db.commit()
    db.close()
    return jsonify({
        "ok": True,
        "alumno": alumno["nombre"] if alumno else alumno_id,
        "estado": "presente",
        "scanned_at": now_iso,
    })


# ─── alumno ──────────────────────────────────────────────────────────────────

@app.get("/api/alumno/clases")
@require_auth("alumno")
def alumno_clases():
    db = get_db()
    rows = db.execute("""
        SELECT c.*, u.nombre as maestro_nombre
        FROM inscripciones i
        JOIN clases c ON c.id = i.clase_id
        JOIN usuarios u ON u.id = c.maestro_id
        WHERE i.alumno_id = ?
        ORDER BY c.nombre
    """, (request.user_id,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.get("/api/alumno/clases/<cid>/qr")
@require_auth("alumno")
def alumno_qr(cid):
    import time
    # Verify enrollment
    db = get_db()
    inscrito = db.execute(
        "SELECT id FROM inscripciones WHERE alumno_id=? AND clase_id=?",
        (request.user_id, cid)
    ).fetchone()
    db.close()
    if not inscrito:
        return jsonify({"error": "No inscrito en esta clase"}), 403

    slot = current_slot()
    fecha = today_str()
    token = build_qr_token(request.user_id, cid, fecha, slot)
    seconds_remaining = QR_REFRESH_SECONDS - (int(time.time()) % QR_REFRESH_SECONDS)

    return jsonify({
        "token": token,
        "slot": slot,
        "fecha": fecha,
        "seconds_remaining": seconds_remaining,
        "refresh_seconds": QR_REFRESH_SECONDS,
    })


@app.get("/api/alumno/clases/<cid>/asistencia-hoy")
@require_auth("alumno")
def alumno_asistencia_hoy(cid):
    db = get_db()
    record = db.execute(
        "SELECT * FROM asistencias WHERE alumno_id=? AND clase_id=? AND fecha=?",
        (request.user_id, cid, today_str())
    ).fetchone()
    db.close()
    return jsonify(dict(record) if record else {"estado": "ausente"})


@app.get("/api/alumno/asistencias")
@require_auth("alumno")
def alumno_todas_asistencias():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM asistencias WHERE alumno_id=? ORDER BY fecha DESC",
        (request.user_id,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ─── run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("✅ Base de datos inicializada")
    print("✅ Admin por defecto: usuario=admin, contraseña=admin123")
    app.run(host="0.0.0.0", port=5000, debug=True)
