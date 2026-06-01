import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "asistencia.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id          TEXT PRIMARY KEY,
            nombre      TEXT NOT NULL,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            rol         TEXT NOT NULL CHECK(rol IN ('admin','maestro','alumno')),
            matricula   TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS clases (
            id          TEXT PRIMARY KEY,
            nombre      TEXT NOT NULL,
            grupo       TEXT NOT NULL,
            horario     TEXT NOT NULL,
            salon       TEXT NOT NULL,
            maestro_id  TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS inscripciones (
            id          TEXT PRIMARY KEY,
            alumno_id   TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            clase_id    TEXT NOT NULL REFERENCES clases(id) ON DELETE CASCADE,
            fecha_alta  TEXT DEFAULT (date('now')),
            UNIQUE(alumno_id, clase_id)
        );

        CREATE TABLE IF NOT EXISTS asistencias (
            id          TEXT PRIMARY KEY,
            clase_id    TEXT NOT NULL REFERENCES clases(id) ON DELETE CASCADE,
            alumno_id   TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            fecha       TEXT NOT NULL,
            estado      TEXT NOT NULL CHECK(estado IN ('presente','tarde','ausente')),
            scanned_at  TEXT,
            UNIQUE(clase_id, alumno_id, fecha)
        );
    """)

    # Create default admin if not exists
    import uuid
    from werkzeug.security import generate_password_hash
    existing = cur.execute("SELECT id FROM usuarios WHERE rol='admin' LIMIT 1").fetchone()
    if not existing:
        cur.execute(
            "INSERT INTO usuarios (id, nombre, username, password, rol) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), "Administrador", "admin",
             generate_password_hash("admin123"), "admin")
        )

    conn.commit()
    conn.close()
