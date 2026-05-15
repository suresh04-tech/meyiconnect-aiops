"""
utils/db.py
───────────
Database connection helper — identical logic to the Lambda version,
adapted for Docker (SSL mode configurable via DB_SSL_MODE env var).
"""

import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager


def get_connection():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", 5432)),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        sslmode=os.environ.get("DB_SSL_MODE", "require"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
