import uuid
import hashlib
import math
import datetime
import cloudinary
import cloudinary.uploader

cloudinary.config(
    cloud_name = "dsgbh0gjs",
    api_key = "841549752716897",
    api_secret = "XGQ5pIl08xO_HtI8f5tWmjDXtHk"
)

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db, init_db
from auth import make_token, require_auth

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=False)

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

# ─── registro público ─────────────────────────────────────────────────────────

@app.route("/api/auth/registro", methods=["POST"])
def registro_usuario():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    nombre = data.get("nombre", "").strip()
    rol = data.get("rol", "").strip()
    codigo_clase = data.get("codigo_clase", "").strip()

    if not username or not password or not nombre or not rol:
        return jsonify({"error": "Todos los campos son obligatorios"}), 400
    if rol not in ["maestro", "alumno"]:
        return jsonify({"error": "Rol inválido"}), 400
    if rol == "alumno" and not codigo_clase:
        return jsonify({"error": "El código de clase es obligatorio"}), 400

    db = get_db()
    existe = db.execute("SELECT id FROM usuarios WHERE username=?", (username,)).fetchone()
    if existe:
        db.close()
        return jsonify({"error": "El usuario ya existe"}), 400

    if rol == "alumno":
        clase = db.execute("SELECT id FROM clases WHERE codigo=?", (codigo_clase,)).fetchone()
        if not clase:
            db.close()
            return jsonify({"error": "Código de clase inválido"}), 400

    hashed = generate_password_hash(password)
    uid = new_id()
    db.execute("INSERT INTO usuarios (id, nombre, username, password, rol) VALUES (?,?,?,?,?)",
               (uid, nombre, username, hashed, rol))
    db.commit()

    if rol == "alumno":
        db.execute("INSERT INTO inscripciones (id, clase_id, alumno_id) VALUES (?,?,?)",
                   (new_id(), clase["id"], uid))
        db.commit()

    db.close()
    return jsonify({"mensaje": "Registro exitoso"}), 201


@app.route("/api/maestro/clases", methods=["POST"])
@require_auth("maestro")
def maestro_create_clase():
    data = request.get_json()
    nombre = (data.get("nombre") or "").strip()
    grupo = (data.get("grupo") or "").strip()
    horario = (data.get("horario") or "").strip()
    salon = (data.get("salon") or "").strip()
    if not nombre or not grupo or not horario or not salon:
        return jsonify({"error": "Todos los campos son requeridos"}), 400
    import random, string
    codigo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    cid = new_id()
    db = get_db()
    db.execute(
        "INSERT INTO clases (id, nombre, grupo, horario, salon, maestro_id, codigo) VALUES (?,?,?,?,?,?,?)",
        (cid, nombre, grupo, horario, salon, request.user_id, codigo)
    )
    db.commit()
    db.close()
    return jsonify({"id": cid, "nombre": nombre, "grupo": grupo, "codigo": codigo}), 201

@app.route("/api/alumno/unirse", methods=["POST"])
@require_auth("alumno")
def alumno_unirse():
    data = request.get_json()
    codigo = data.get("codigo", "").strip()
    if not codigo:
        return jsonify({"error": "Código requerido"}), 400
    db = get_db()
    clase = db.execute("SELECT id, nombre FROM clases WHERE codigo=?", (codigo,)).fetchone()
    if not clase:
        db.close()
        return jsonify({"error": "Código de clase inválido"}), 400
    ya_inscrito = db.execute(
        "SELECT id FROM inscripciones WHERE alumno_id=? AND clase_id=?",
        (request.user_id, clase["id"])
    ).fetchone()
    if ya_inscrito:
        db.close()
        return jsonify({"error": "Ya estás inscrito en esta clase"}), 400
    db.execute("INSERT INTO inscripciones (id, clase_id, alumno_id) VALUES (?,?,?)",
               (new_id(), clase["id"], request.user_id))
    db.commit()
    db.close()
    return jsonify({"mensaje": f"Te uniste a {clase['nombre']}"}), 201

# ─── tareas ──────────────────────────────────────────────────────────────────

@app.get("/api/maestro/clases/<cid>/tareas")
@require_auth("maestro")
def maestro_list_tareas(cid):
    db = get_db()
    rows = db.execute("SELECT * FROM tareas WHERE clase_id=? ORDER BY created_at DESC", (cid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/maestro/clases/<cid>/tareas")
@require_auth("maestro")
def maestro_create_tarea(cid):
    data = request.get_json()
    titulo = (data.get("titulo") or "").strip()
    descripcion = (data.get("descripcion") or "").strip()
    fecha_limite = (data.get("fecha_limite") or "").strip()
    if not titulo:
        return jsonify({"error": "El título es obligatorio"}), 400
    tid = new_id()
    db = get_db()
    db.execute("INSERT INTO tareas (id, clase_id, titulo, descripcion, fecha_limite) VALUES (?,?,?,?,?)",
               (tid, cid, titulo, descripcion, fecha_limite))
    db.commit()
    db.close()
    return jsonify({"id": tid, "titulo": titulo}), 201

@app.delete("/api/maestro/tareas/<tid>")
@require_auth("maestro")
def maestro_delete_tarea(tid):
    db = get_db()
    db.execute("DELETE FROM tareas WHERE id=?", (tid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.get("/api/maestro/tareas/<tid>/entregas")
@require_auth("maestro")
def maestro_list_entregas(tid):
    db = get_db()
    rows = db.execute("""
        SELECT e.*, u.nombre as alumno_nombre
        FROM entregas e
        JOIN usuarios u ON u.id = e.alumno_id
        WHERE e.tarea_id=?
        ORDER BY e.created_at DESC
    """, (tid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/maestro/entregas/<eid>/calificar")
@require_auth("maestro")
def maestro_calificar(eid):
    data = request.get_json()
    calificacion = data.get("calificacion")
    db = get_db()
    db.execute("UPDATE entregas SET calificacion=? WHERE id=?", (calificacion, eid))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.get("/api/alumno/clases/<cid>/tareas")
@require_auth("alumno")
def alumno_list_tareas(cid):
    db = get_db()
    rows = db.execute("SELECT * FROM tareas WHERE clase_id=? ORDER BY created_at DESC", (cid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/alumno/tareas/<tid>/entregar")
@require_auth("alumno")
def alumno_entregar(tid):
    if 'archivo' not in request.files:
        return jsonify({"error": "No se envió archivo"}), 400
    archivo = request.files['archivo']
    try:
        result = cloudinary.uploader.upload(archivo, resource_type="raw", folder="tareas")
        url = result["secure_url"]
        nombre = archivo.filename
    except Exception as e:
        return jsonify({"error": f"Error al subir archivo: {str(e)}"}), 500
    db = get_db()
    eid = new_id()
    try:
        db.execute("INSERT INTO entregas (id, tarea_id, alumno_id, archivo_url, archivo_nombre) VALUES (?,?,?,?,?)",
                   (eid, tid, request.user_id, url, nombre))
        db.commit()
    except Exception:
        db.execute("UPDATE entregas SET archivo_url=?, archivo_nombre=?, created_at=datetime('now') WHERE tarea_id=? AND alumno_id=?",
                   (url, nombre, tid, request.user_id))
        db.commit()
    db.close()
    return jsonify({"ok": True, "url": url}), 201

@app.get("/api/alumno/tareas/<tid>/mi-entrega")
@require_auth("alumno")
def alumno_mi_entrega(tid):
    db = get_db()
    row = db.execute("SELECT * FROM entregas WHERE tarea_id=? AND alumno_id=?",
                     (tid, request.user_id)).fetchone()
    db.close()
    return jsonify(dict(row) if row else {})
# ─── anuncios ─────────────────────────────────────────────────────────────────

@app.get("/api/maestro/clases/<cid>/anuncios")
@require_auth("maestro")
def maestro_list_anuncios(cid):
    db = get_db()
    rows = db.execute("SELECT * FROM anuncios WHERE clase_id=? ORDER BY created_at DESC", (cid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/maestro/clases/<cid>/anuncios")
@require_auth("maestro")
def maestro_create_anuncio(cid):
    data = request.get_json()
    titulo = (data.get("titulo") or "").strip()
    contenido = (data.get("contenido") or "").strip()
    if not titulo or not contenido:
        return jsonify({"error": "Título y contenido son obligatorios"}), 400
    aid = new_id()
    db = get_db()
    db.execute("INSERT INTO anuncios (id, clase_id, titulo, contenido) VALUES (?,?,?,?)",
               (aid, cid, titulo, contenido))
    db.commit()
    db.close()
    return jsonify({"id": aid, "titulo": titulo}), 201

@app.delete("/api/maestro/anuncios/<aid>")
@require_auth("maestro")
def maestro_delete_anuncio(aid):
    db = get_db()
    db.execute("DELETE FROM anuncios WHERE id=?", (aid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.get("/api/alumno/clases/<cid>/anuncios")
@require_auth("alumno")
def alumno_list_anuncios(cid):
    db = get_db()
    rows = db.execute("SELECT * FROM anuncios WHERE clase_id=? ORDER BY created_at DESC", (cid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

# ─── examenes ─────────────────────────────────────────────────────────────────

@app.get("/api/maestro/clases/<cid>/examenes")
@require_auth("maestro")
def maestro_list_examenes(cid):
    db = get_db()
    rows = db.execute("SELECT * FROM examenes WHERE clase_id=? ORDER BY created_at DESC", (cid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/maestro/clases/<cid>/examenes")
@require_auth("maestro")
def maestro_create_examen(cid):
    data = request.get_json()
    titulo = (data.get("titulo") or "").strip()
    descripcion = (data.get("descripcion") or "").strip()
    preguntas = data.get("preguntas", [])
    if not titulo or not preguntas:
        return jsonify({"error": "Título y preguntas son obligatorios"}), 400
    eid = new_id()
    db = get_db()
    db.execute("INSERT INTO examenes (id, clase_id, titulo, descripcion) VALUES (?,?,?,?)",
               (eid, cid, titulo, descripcion))
    for p in preguntas:
        pid = new_id()
        db.execute("INSERT INTO preguntas (id, examen_id, texto, opcion_a, opcion_b, opcion_c, opcion_d, correcta) VALUES (?,?,?,?,?,?,?,?)",
                   (pid, eid, p["texto"], p["opcion_a"], p["opcion_b"], p["opcion_c"], p["opcion_d"], p["correcta"]))
    db.commit()
    db.close()
    return jsonify({"id": eid, "titulo": titulo}), 201

@app.delete("/api/maestro/examenes/<eid>")
@require_auth("maestro")
def maestro_delete_examen(eid):
    db = get_db()
    db.execute("DELETE FROM examenes WHERE id=?", (eid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.get("/api/maestro/examenes/<eid>/resultados")
@require_auth("maestro")
def maestro_resultados_examen(eid):
    db = get_db()
    rows = db.execute("""
        SELECT r.*, u.nombre as alumno_nombre
        FROM respuestas_examen r
        JOIN usuarios u ON u.id = r.alumno_id
        WHERE r.examen_id=?
        ORDER BY r.created_at DESC
    """, (eid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.get("/api/alumno/clases/<cid>/examenes")
@require_auth("alumno")
def alumno_list_examenes(cid):
    db = get_db()
    rows = db.execute("SELECT * FROM examenes WHERE clase_id=? AND activo=1 ORDER BY created_at DESC", (cid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.get("/api/alumno/examenes/<eid>")
@require_auth("alumno")
def alumno_get_examen(eid):
    db = get_db()
    examen = db.execute("SELECT * FROM examenes WHERE id=?", (eid,)).fetchone()
    if not examen:
        db.close()
        return jsonify({"error": "Examen no encontrado"}), 404
    ya_respondio = db.execute(
        "SELECT id FROM respuestas_examen WHERE examen_id=? AND alumno_id=?",
        (eid, request.user_id)
    ).fetchone()
    if ya_respondio:
        db.close()
        return jsonify({"error": "Ya respondiste este examen"}), 400
    preguntas = db.execute(
        "SELECT id, texto, opcion_a, opcion_b, opcion_c, opcion_d FROM preguntas WHERE examen_id=?",
        (eid,)
    ).fetchall()
    db.close()
    return jsonify({"examen": dict(examen), "preguntas": [dict(p) for p in preguntas]})

@app.post("/api/alumno/examenes/<eid>/responder")
@require_auth("alumno")
def alumno_responder_examen(eid):
    data = request.get_json()
    respuestas = data.get("respuestas", {})
    db = get_db()
    ya_respondio = db.execute(
        "SELECT id FROM respuestas_examen WHERE examen_id=? AND alumno_id=?",
        (eid, request.user_id)
    ).fetchone()
    if ya_respondio:
        db.close()
        return jsonify({"error": "Ya respondiste este examen"}), 400
    preguntas = db.execute("SELECT * FROM preguntas WHERE examen_id=?", (eid,)).fetchall()
    correctas = 0
    for p in preguntas:
        if respuestas.get(p["id"]) == p["correcta"]:
            correctas += 1
    calificacion = round((correctas / len(preguntas)) * 10, 1) if preguntas else 0
    rid = new_id()
    db.execute("INSERT INTO respuestas_examen (id, examen_id, alumno_id, calificacion) VALUES (?,?,?,?)",
               (rid, eid, request.user_id, calificacion))
    for pid, resp in respuestas.items():
        db.execute("INSERT INTO respuestas_pregunta (id, respuesta_examen_id, pregunta_id, respuesta) VALUES (?,?,?,?)",
                   (new_id(), rid, pid, resp))
    db.commit()
    db.close()
    return jsonify({"calificacion": calificacion, "correctas": correctas, "total": len(preguntas)}), 201

# ─── comentarios ─────────────────────────────────────────────────────────────

@app.post("/api/alumno/comentarios")
@require_auth("alumno")
def alumno_crear_comentario():
    data = request.get_json()
    tipo = data.get("tipo", "").strip()
    referencia_id = data.get("referencia_id", "").strip()
    mensaje = data.get("mensaje", "").strip()
    if not tipo or not referencia_id or not mensaje:
        return jsonify({"error": "Todos los campos son obligatorios"}), 400
    cid = new_id()
    db = get_db()
    db.execute("INSERT INTO comentarios (id, tipo, referencia_id, alumno_id, mensaje) VALUES (?,?,?,?,?)",
               (cid, tipo, referencia_id, request.user_id, mensaje))
    db.commit()
    db.close()
    return jsonify({"id": cid}), 201

@app.get("/api/alumno/comentarios/<tipo>/<referencia_id>")
@require_auth("alumno")
def alumno_get_comentarios(tipo, referencia_id):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM comentarios WHERE tipo=? AND referencia_id=? AND alumno_id=? ORDER BY created_at ASC",
        (tipo, referencia_id, request.user_id)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.get("/api/maestro/comentarios/<tipo>/<referencia_id>")
@require_auth("maestro")
def maestro_get_comentarios(tipo, referencia_id):
    db = get_db()
    rows = db.execute("""
        SELECT c.*, u.nombre as alumno_nombre
        FROM comentarios c
        JOIN usuarios u ON u.id = c.alumno_id
        WHERE c.tipo=? AND c.referencia_id=?
        ORDER BY c.created_at ASC
    """, (tipo, referencia_id)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/maestro/comentarios/<cid>/responder")
@require_auth("maestro")
def maestro_responder_comentario(cid):
    data = request.get_json()
    respuesta = data.get("respuesta", "").strip()
    if not respuesta:
        return jsonify({"error": "Respuesta requerida"}), 400
    db = get_db()
    db.execute("UPDATE comentarios SET respuesta=? WHERE id=?", (respuesta, cid))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.get("/api/alumno/comentarios/anuncio/<referencia_id>/publico")
@require_auth("alumno")
def alumno_get_comentarios_publicos(referencia_id):
    db = get_db()
    rows = db.execute("""
        SELECT c.*, u.nombre as alumno_nombre
        FROM comentarios c
        JOIN usuarios u ON u.id = c.alumno_id
        WHERE c.tipo='anuncio' AND c.referencia_id=?
        ORDER BY c.created_at ASC
    """, (referencia_id,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    print("✅ Base de datos inicializada")
    print("✅ Admin por defecto: usuario=admin, contraseña=admin123")
    app.run(host="0.0.0.0", port=5000, debug=True)

# Migración: agregar columna codigo si no existe
try:
    db = get_db()
    db.execute("ALTER TABLE clases ADD COLUMN codigo TEXT UNIQUE")
    db.commit()
    db.close()
    print("✅ Migración: columna codigo agregada")
except:
    pass
