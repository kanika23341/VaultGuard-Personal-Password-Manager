import sqlite3
from pathlib import Path
from contextlib import contextmanager

ROOT=Path(__file__).resolve().parents[2]
dataDir=ROOT/"data"
dbPath=dataDir/"vault.db"

@contextmanager
def get_connection():
    dataDir.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(dbPath)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_metadata(
                id INTEGER PRIMARY KEY CHECK (id=1),
                salt BLOB NOT NULL,
                verifier TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials(
                id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

def get_vault_metadata():
    with get_connection() as conn:
        return conn.execute("SELECT salt, verifier FROM vault_metadata WHERE id=1").fetchone()

def create_vault_metadata(salt: bytes, verifier: str):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO vault_metadata (id, salt, verifier) VALUES (1, ?, ?)",
            (salt, verifier),
        )

def list_encrypted_credentials():
    with get_connection() as conn:
        rows=conn.execute("""
            SELECT id, nonce, ciphertext, created_at, updated_at
            FROM credentials
            ORDER BY created_at DESC
        """).fetchall()
        return [dict(row) for row in rows]

def get_encrypted_credential(credential_id: str):
    with get_connection() as conn:
        row= conn.execute("""
            SELECT id, nonce, ciphertext, created_at, updated_at
            FROM credentials
            WHERE id=? 
        """,(credential_id,)).fetchone()
        return dict(row) if row else None

def insert_credential(credential_id: str, nonce: str, ciphertext: str, timestamp: str,):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO credentials (id, nonce, ciphertext, created_at, updated_at)
            VALUES (?,?,?,?,?)
        """,(
            credential_id, nonce, ciphertext, timestamp, timestamp
        ))

def update_credential(credential_id: str, nonce: str, ciphertext: str, timestamp: str,):
    with get_connection() as conn:
        cursor=conn.execute("""
            UPDATE credentials
            SET nonce=?, ciphertext=?, updated_at=?
            WHERE id=?
        """,(nonce, ciphertext, timestamp, credential_id))
        return cursor.rowcount==1

def delete_credential(credential_id: str):
    with get_connection() as conn:
        cursor=conn.execute("""
            "DELETE FROM credentials WHERE id=?",
            (credential_id,),
        """)
        return cursor.rowcount==1

    