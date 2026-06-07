import uuid
import hashlib
import math
import datetime
import cloudinary
import cloudinary.uploader
import psycopg2
import psycopg2.extras
import resend
import random

resend.api_key = "re_46Q2oL6T_3rUKVMCMnEAhKzxfzmb3MTY7"

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
        return False, "Firma del QR inválida"
    active = current_slot()
    if slot < active - 1 or slot > active:
        return False, "QR expirado"
    return True, alumno_id

def fetchone(cur):
    row = cur.fetchone()
    return dict(row) if row else None

def fetchall(cur):
    return [dict(r) for r in cur.fetchall()]

def db_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# ─── auth ────────────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
def login():
    data = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "Usuario y contraseña requeridos"}), 400
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
    user = fetchone(cur)
    conn.close()
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Credenciales incorrectas"}), 401
    token = make_token(user["id"], user["rol"])
    return jsonify({"token": token, "user": {"id": user["id"], "nombre": user["nombre"], "username": user["username"], "rol": user["rol"], "matricula": user["matricula"]}})

@app.get("/api/auth/me")
@require_auth("admin", "maestro", "alumno")
def me():
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT id, nombre, username, rol, matricula FROM usuarios WHERE id=%s", (request.user_id,))
    user = fetchone(cur)
    conn.close()
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    return jsonify(user)

@app.route("/api/auth/verificar", methods=["POST"])
def verificar_codigo():
    data = request.get_json()
    email = data.get("email", "").strip()
    codigo = data.get("codigo", "").strip()
    
    if not email or not codigo:
        return jsonify({"error": "Email y código son obligatorios"}), 400
    
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM verificaciones WHERE email=%s AND codigo=%s AND usado=0 ORDER BY created_at DESC LIMIT 1", (email, codigo))
    verificacion = fetchone(cur)
    
    if not verificacion:
        conn.close()
        return jsonify({"error": "Código inválido o expirado"}), 400
    
    cur.execute("UPDATE verificaciones SET usado=1 WHERE id=%s", (verificacion["id"],))
    conn.commit()
    conn.close()
    
    return jsonify({"mensaje": "Correo verificado exitosamente"}), 200

# ─── maestro ─────────────────────────────────────────────────────────────────

@app.get("/api/maestro/clases")
@require_auth("maestro")
def maestro_clases():
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM clases WHERE maestro_id=%s ORDER BY nombre", (request.user_id,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

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
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("INSERT INTO clases (id, nombre, grupo, horario, salon, maestro_id, codigo) VALUES (%s,%s,%s,%s,%s,%s,%s)", (cid, nombre, grupo, horario, salon, request.user_id, codigo))
    conn.commit()
    conn.close()
    return jsonify({"id": cid, "nombre": nombre, "grupo": grupo, "codigo": codigo}), 201

@app.get("/api/maestro/clases/<cid>/alumnos")
@require_auth("maestro")
def maestro_alumnos(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT id FROM clases WHERE id=%s AND maestro_id=%s", (cid, request.user_id))
    if not fetchone(cur):
        conn.close()
        return jsonify({"error": "Clase no encontrada"}), 404
    cur.execute("SELECT u.id, u.nombre, u.username, u.matricula FROM inscripciones i JOIN usuarios u ON u.id = i.alumno_id WHERE i.clase_id = %s ORDER BY u.nombre", (cid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.get("/api/maestro/clases/<cid>/asistencias")
@require_auth("maestro")
def maestro_asistencias(cid):
    fecha = request.args.get("fecha", today_str())
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM asistencias WHERE clase_id=%s AND fecha=%s", (cid, fecha))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.get("/api/maestro/clases/<cid>/asistencias/historico")
@require_auth("maestro")
def maestro_historico(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM asistencias WHERE clase_id=%s ORDER BY fecha DESC, scanned_at DESC", (cid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.post("/api/maestro/clases/<cid>/escanear")
@require_auth("maestro")
def escanear_qr(cid):
    data = request.get_json()
    token = data.get("token", "")
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM clases WHERE id=%s AND maestro_id=%s", (cid, request.user_id))
    if not fetchone(cur):
        conn.close()
        return jsonify({"error": "Clase no encontrada"}), 404
    valid, result = validate_qr_token(token, cid)
    if not valid:
        conn.close()
        return jsonify({"error": result}), 400
    alumno_id = result
    cur.execute("SELECT id FROM inscripciones WHERE alumno_id=%s AND clase_id=%s", (alumno_id, cid))
    if not fetchone(cur):
        conn.close()
        return jsonify({"error": "El alumno no está inscrito en esta clase"}), 400
    cur.execute("SELECT nombre FROM usuarios WHERE id=%s", (alumno_id,))
    alumno = fetchone(cur)
    fecha = today_str()
    now_iso = datetime.datetime.now().isoformat()
    record_id = f"{cid}-{alumno_id}-{fecha}"
    cur.execute("SELECT * FROM asistencias WHERE id=%s", (record_id,))
    if fetchone(cur):
        cur.execute("UPDATE asistencias SET estado='presente', scanned_at=%s WHERE id=%s", (now_iso, record_id))
    else:
        cur.execute("INSERT INTO asistencias (id, clase_id, alumno_id, fecha, estado, scanned_at) VALUES (%s,%s,%s,%s,%s,%s)", (record_id, cid, alumno_id, fecha, "presente", now_iso))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "alumno": alumno["nombre"] if alumno else alumno_id, "estado": "presente", "scanned_at": now_iso})

# ─── alumno ──────────────────────────────────────────────────────────────────

@app.get("/api/alumno/clases")
@require_auth("alumno")
def alumno_clases():
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT c.*, u.nombre as maestro_nombre FROM inscripciones i JOIN clases c ON c.id = i.clase_id JOIN usuarios u ON u.id = c.maestro_id WHERE i.alumno_id = %s ORDER BY c.nombre", (request.user_id,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.get("/api/alumno/clases/<cid>/qr")
@require_auth("alumno")
def alumno_qr(cid):
    import time
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT id FROM inscripciones WHERE alumno_id=%s AND clase_id=%s", (request.user_id, cid))
    if not fetchone(cur):
        conn.close()
        return jsonify({"error": "No inscrito en esta clase"}), 403
    conn.close()
    slot = current_slot()
    fecha = today_str()
    token = build_qr_token(request.user_id, cid, fecha, slot)
    seconds_remaining = QR_REFRESH_SECONDS - (int(time.time()) % QR_REFRESH_SECONDS)
    return jsonify({"token": token, "slot": slot, "fecha": fecha, "seconds_remaining": seconds_remaining, "refresh_seconds": QR_REFRESH_SECONDS})

@app.get("/api/alumno/clases/<cid>/asistencia-hoy")
@require_auth("alumno")
def alumno_asistencia_hoy(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM asistencias WHERE alumno_id=%s AND clase_id=%s AND fecha=%s", (request.user_id, cid, today_str()))
    record = fetchone(cur)
    conn.close()
    return jsonify(record if record else {"estado": "ausente"})

@app.route("/api/alumno/unirse", methods=["POST"])
@require_auth("alumno")
def alumno_unirse():
    data = request.get_json()
    codigo = data.get("codigo", "").strip()
    if not codigo:
        return jsonify({"error": "Código requerido"}), 400
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT id, nombre FROM clases WHERE codigo=%s", (codigo,))
    clase = fetchone(cur)
    if not clase:
        conn.close()
        return jsonify({"error": "Código de clase inválido"}), 400
    cur.execute("SELECT id FROM inscripciones WHERE alumno_id=%s AND clase_id=%s", (request.user_id, clase["id"]))
    if fetchone(cur):
        conn.close()
        return jsonify({"error": "Ya estás inscrito en esta clase"}), 400
    cur.execute("INSERT INTO inscripciones (id, clase_id, alumno_id) VALUES (%s,%s,%s)", (new_id(), clase["id"], request.user_id))
    conn.commit()
    conn.close()
    return jsonify({"mensaje": f"Te uniste a {clase['nombre']}"}), 201

# ─── tareas ──────────────────────────────────────────────────────────────────

@app.get("/api/maestro/clases/<cid>/tareas")
@require_auth("maestro")
def maestro_list_tareas(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM tareas WHERE clase_id=%s ORDER BY created_at DESC", (cid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

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
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("INSERT INTO tareas (id, clase_id, titulo, descripcion, fecha_limite) VALUES (%s,%s,%s,%s,%s)", (tid, cid, titulo, descripcion, fecha_limite))
    conn.commit()
    conn.close()
    return jsonify({"id": tid, "titulo": titulo}), 201

@app.delete("/api/maestro/tareas/<tid>")
@require_auth("maestro")
def maestro_delete_tarea(tid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("DELETE FROM tareas WHERE id=%s", (tid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/maestro/tareas/<tid>/entregas")
@require_auth("maestro")
def maestro_list_entregas(tid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT e.*, u.nombre as alumno_nombre FROM entregas e JOIN usuarios u ON u.id = e.alumno_id WHERE e.tarea_id=%s ORDER BY e.created_at DESC", (tid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.post("/api/maestro/entregas/<eid>/calificar")
@require_auth("maestro")
def maestro_calificar(eid):
    data = request.get_json()
    calificacion = data.get("calificacion")
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("UPDATE entregas SET calificacion=%s WHERE id=%s", (calificacion, eid))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/alumno/clases/<cid>/tareas")
@require_auth("alumno")
def alumno_list_tareas(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM tareas WHERE clase_id=%s ORDER BY created_at DESC", (cid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

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
    conn = get_db()
    cur = db_cursor(conn)
    eid = new_id()
    try:
        cur.execute("INSERT INTO entregas (id, tarea_id, alumno_id, archivo_url, archivo_nombre) VALUES (%s,%s,%s,%s,%s)", (eid, tid, request.user_id, url, nombre))
        conn.commit()
    except Exception:
        conn.rollback()
        cur.execute("UPDATE entregas SET archivo_url=%s, archivo_nombre=%s WHERE tarea_id=%s AND alumno_id=%s", (url, nombre, tid, request.user_id))
        conn.commit()
    conn.close()
    return jsonify({"ok": True, "url": url}), 201

@app.get("/api/alumno/tareas/<tid>/mi-entrega")
@require_auth("alumno")
def alumno_mi_entrega(tid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM entregas WHERE tarea_id=%s AND alumno_id=%s", (tid, request.user_id))
    row = fetchone(cur)
    conn.close()
    return jsonify(row if row else {})

# ─── anuncios ─────────────────────────────────────────────────────────────────

@app.get("/api/maestro/clases/<cid>/anuncios")
@require_auth("maestro")
def maestro_list_anuncios(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM anuncios WHERE clase_id=%s ORDER BY created_at DESC", (cid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.post("/api/maestro/clases/<cid>/anuncios")
@require_auth("maestro")
def maestro_create_anuncio(cid):
    data = request.get_json()
    titulo = (data.get("titulo") or "").strip()
    contenido = (data.get("contenido") or "").strip()
    if not titulo or not contenido:
        return jsonify({"error": "Título y contenido son obligatorios"}), 400
    aid = new_id()
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("INSERT INTO anuncios (id, clase_id, titulo, contenido) VALUES (%s,%s,%s,%s)", (aid, cid, titulo, contenido))
    conn.commit()
    conn.close()
    return jsonify({"id": aid, "titulo": titulo}), 201

@app.delete("/api/maestro/anuncios/<aid>")
@require_auth("maestro")
def maestro_delete_anuncio(aid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("DELETE FROM anuncios WHERE id=%s", (aid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/alumno/clases/<cid>/anuncios")
@require_auth("alumno")
def alumno_list_anuncios(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM anuncios WHERE clase_id=%s ORDER BY created_at DESC", (cid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

# ─── examenes ─────────────────────────────────────────────────────────────────

@app.get("/api/maestro/clases/<cid>/examenes")
@require_auth("maestro")
def maestro_list_examenes(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM examenes WHERE clase_id=%s ORDER BY created_at DESC", (cid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

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
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("INSERT INTO examenes (id, clase_id, titulo, descripcion) VALUES (%s,%s,%s,%s)", (eid, cid, titulo, descripcion))
    for p in preguntas:
        pid = new_id()
        cur.execute("INSERT INTO preguntas (id, examen_id, texto, opcion_a, opcion_b, opcion_c, opcion_d, correcta) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (pid, eid, p["texto"], p["opcion_a"], p["opcion_b"], p["opcion_c"], p["opcion_d"], p["correcta"]))
    conn.commit()
    conn.close()
    return jsonify({"id": eid, "titulo": titulo}), 201

@app.delete("/api/maestro/examenes/<eid>")
@require_auth("maestro")
def maestro_delete_examen(eid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("DELETE FROM examenes WHERE id=%s", (eid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/maestro/examenes/<eid>/resultados")
@require_auth("maestro")
def maestro_resultados_examen(eid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT r.*, u.nombre as alumno_nombre FROM respuestas_examen r JOIN usuarios u ON u.id = r.alumno_id WHERE r.examen_id=%s ORDER BY r.created_at DESC", (eid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.get("/api/alumno/clases/<cid>/examenes")
@require_auth("alumno")
def alumno_list_examenes(cid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM examenes WHERE clase_id=%s AND activo=1 ORDER BY created_at DESC", (cid,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.get("/api/alumno/examenes/<eid>")
@require_auth("alumno")
def alumno_get_examen(eid):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM examenes WHERE id=%s", (eid,))
    examen = fetchone(cur)
    if not examen:
        conn.close()
        return jsonify({"error": "Examen no encontrado"}), 404
    cur.execute("SELECT id FROM respuestas_examen WHERE examen_id=%s AND alumno_id=%s", (eid, request.user_id))
    if fetchone(cur):
        conn.close()
        return jsonify({"error": "Ya respondiste este examen"}), 400
    cur.execute("SELECT id, texto, opcion_a, opcion_b, opcion_c, opcion_d FROM preguntas WHERE examen_id=%s", (eid,))
    preguntas = fetchall(cur)
    conn.close()
    return jsonify({"examen": examen, "preguntas": preguntas})

@app.post("/api/alumno/examenes/<eid>/responder")
@require_auth("alumno")
def alumno_responder_examen(eid):
    data = request.get_json()
    respuestas = data.get("respuestas", {})
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT id FROM respuestas_examen WHERE examen_id=%s AND alumno_id=%s", (eid, request.user_id))
    if fetchone(cur):
        conn.close()
        return jsonify({"error": "Ya respondiste este examen"}), 400
    cur.execute("SELECT * FROM preguntas WHERE examen_id=%s", (eid,))
    preguntas = fetchall(cur)
    correctas = sum(1 for p in preguntas if respuestas.get(p["id"]) == p["correcta"])
    calificacion = round((correctas / len(preguntas)) * 10, 1) if preguntas else 0
    rid = new_id()
    cur.execute("INSERT INTO respuestas_examen (id, examen_id, alumno_id, calificacion) VALUES (%s,%s,%s,%s)", (rid, eid, request.user_id, calificacion))
    for pid, resp in respuestas.items():
        cur.execute("INSERT INTO respuestas_pregunta (id, respuesta_examen_id, pregunta_id, respuesta) VALUES (%s,%s,%s,%s)", (new_id(), rid, pid, resp))
    conn.commit()
    conn.close()
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
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("INSERT INTO comentarios (id, tipo, referencia_id, alumno_id, mensaje) VALUES (%s,%s,%s,%s,%s)", (cid, tipo, referencia_id, request.user_id, mensaje))
    conn.commit()
    conn.close()
    return jsonify({"id": cid}), 201

@app.get("/api/alumno/comentarios/<tipo>/<referencia_id>")
@require_auth("alumno")
def alumno_get_comentarios(tipo, referencia_id):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT * FROM comentarios WHERE tipo=%s AND referencia_id=%s AND alumno_id=%s ORDER BY created_at ASC", (tipo, referencia_id, request.user_id))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.get("/api/maestro/comentarios/<tipo>/<referencia_id>")
@require_auth("maestro")
def maestro_get_comentarios(tipo, referencia_id):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT c.*, u.nombre as alumno_nombre FROM comentarios c JOIN usuarios u ON u.id = c.alumno_id WHERE c.tipo=%s AND c.referencia_id=%s ORDER BY c.created_at ASC", (tipo, referencia_id))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

@app.post("/api/maestro/comentarios/<cid>/responder")
@require_auth("maestro")
def maestro_responder_comentario(cid):
    data = request.get_json()
    respuesta = data.get("respuesta", "").strip()
    if not respuesta:
        return jsonify({"error": "Respuesta requerida"}), 400
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("UPDATE comentarios SET respuesta=%s WHERE id=%s", (respuesta, cid))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/alumno/comentarios/anuncio/<referencia_id>/publico")
@require_auth("alumno")
def alumno_get_comentarios_publicos(referencia_id):
    conn = get_db()
    cur = db_cursor(conn)
    cur.execute("SELECT c.*, u.nombre as alumno_nombre FROM comentarios c JOIN usuarios u ON u.id = c.alumno_id WHERE c.tipo='anuncio' AND c.referencia_id=%s ORDER BY c.created_at ASC", (referencia_id,))
    rows = fetchall(cur)
    conn.close()
    return jsonify(rows)

if __name__ == "__main__":
    init_db()
    print("✅ Base de datos PostgreSQL inicializada")
    app.run(host="0.0.0.0", port=5000, debug=True)