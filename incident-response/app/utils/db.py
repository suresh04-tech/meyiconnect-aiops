import os
import json
import psycopg2
import psycopg2.extras
from contextlib import contextmanager

# ─── DB Connection ────────────────────────────────────────────────────────────

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


# ─── HTTP Response Helpers ────────────────────────────────────────────────────

def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }


def ok(body: dict) -> dict:
    return _response(200, body)


def created(body: dict) -> dict:
    return _response(201, body)


def bad_request(message: str) -> dict:
    return _response(400, {"error": message})


def not_found(message: str) -> dict:
    return _response(404, {"error": message})


def server_error(message: str) -> dict:
    return _response(500, {"error": message})
