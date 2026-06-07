import os
import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://neondb_owner:npg_RN8EeQfFpV1A@ep-wandering-pond-aqj6yism-pooler.c-8.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require')

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id          TEXT PRIMARY KEY,
            nombre      TEXT NOT NULL,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            rol         TEXT NOT NULL CHECK(rol IN ('admin','maestro','alumno')),
            matricula   TEXT,
            email       TEXT,
            created_at  TEXT DEFAULT (now()::text)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS clases (
            id          TEXT PRIMARY KEY,
            nombre      TEXT NOT NULL,
            grupo       TEXT NOT NULL,
            horario     TEXT NOT NULL,
            salon       TEXT NOT NULL,
            maestro_id  TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            codigo      TEXT UNIQUE,
            created_at  TEXT DEFAULT (now()::text)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS inscripciones (
            id          TEXT PRIMARY KEY,
            alumno_id   TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            clase_id    TEXT NOT NULL REFERENCES clases(id) ON DELETE CASCADE,
            fecha_alta  TEXT DEFAULT (now()::text),
            UNIQUE(alumno_id, clase_id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS asistencias (
            id          TEXT PRIMARY KEY,
            clase_id    TEXT NOT NULL REFERENCES clases(id) ON DELETE CASCADE,
            alumno_id   TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            fecha       TEXT NOT NULL,
            estado      TEXT NOT NULL CHECK(estado IN ('presente','tarde','ausente')),
            scanned_at  TEXT,
            UNIQUE(clase_id, alumno_id, fecha)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tareas (
            id          TEXT PRIMARY KEY,
            clase_id    TEXT NOT NULL REFERENCES clases(id) ON DELETE CASCADE,
            titulo      TEXT NOT NULL,
            descripcion TEXT,
            fecha_limite TEXT,
            created_at  TEXT DEFAULT (now()::text)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS entregas (
            id          TEXT PRIMARY KEY,
            tarea_id    TEXT NOT NULL REFERENCES tareas(id) ON DELETE CASCADE,
            alumno_id   TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            archivo_url TEXT NOT NULL,
            archivo_nombre TEXT,
            comentario  TEXT,
            calificacion REAL,
            created_at  TEXT DEFAULT (now()::text),
            UNIQUE(tarea_id, alumno_id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS anuncios (
            id          TEXT PRIMARY KEY,
            clase_id    TEXT NOT NULL REFERENCES clases(id) ON DELETE CASCADE,
            titulo      TEXT NOT NULL,
            contenido   TEXT NOT NULL,
            created_at  TEXT DEFAULT (now()::text)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS examenes (
            id          TEXT PRIMARY KEY,
            clase_id    TEXT NOT NULL REFERENCES clases(id) ON DELETE CASCADE,
            titulo      TEXT NOT NULL,
            descripcion TEXT,
            activo      INTEGER DEFAULT 1,
            created_at  TEXT DEFAULT (now()::text)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS preguntas (
            id          TEXT PRIMARY KEY,
            examen_id   TEXT NOT NULL REFERENCES examenes(id) ON DELETE CASCADE,
            texto       TEXT NOT NULL,
            opcion_a    TEXT NOT NULL,
            opcion_b    TEXT NOT NULL,
            opcion_c    TEXT NOT NULL,
            opcion_d    TEXT NOT NULL,
            correcta    TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS respuestas_examen (
            id          TEXT PRIMARY KEY,
            examen_id   TEXT NOT NULL REFERENCES examenes(id) ON DELETE CASCADE,
            alumno_id   TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            calificacion REAL,
            created_at  TEXT DEFAULT (now()::text),
            UNIQUE(examen_id, alumno_id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS respuestas_pregunta (
            id          TEXT PRIMARY KEY,
            respuesta_examen_id TEXT NOT NULL REFERENCES respuestas_examen(id) ON DELETE CASCADE,
            pregunta_id TEXT NOT NULL REFERENCES preguntas(id) ON DELETE CASCADE,
            respuesta   TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS comentarios (
            id          TEXT PRIMARY KEY,
            tipo        TEXT NOT NULL,
            referencia_id TEXT NOT NULL,
            alumno_id   TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            mensaje     TEXT NOT NULL,
            respuesta   TEXT,
            created_at  TEXT DEFAULT (now()::text)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS verificaciones (
            id          TEXT PRIMARY KEY,
            email       TEXT NOT NULL,
            codigo      TEXT NOT NULL,
            usado       INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (now()::text)
        )
    """)

    # Admin por defecto
    import uuid
    from werkzeug.security import generate_password_hash
    cur.execute("SELECT id FROM usuarios WHERE rol='admin' LIMIT 1")
    existing = cur.fetchone()
    if not existing:
        cur.execute(
            "INSERT INTO usuarios (id, nombre, username, password, rol) VALUES (%s,%s,%s,%s,%s)",
            (str(uuid.uuid4()), "Administrador", "admin",
             generate_password_hash("admin123"), "admin")
        )

    conn.commit()
    cur.close()
    conn.close()
