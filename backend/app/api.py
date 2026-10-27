
import base64
import json
import secrets
import time
import uuid
from datetime import datetime, timezone
from threading import RLock
from typing import Annotated
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from backend.app.crypto import (decrypt_bytes,derive_key,encrypt_bytes,generate_salt,)
from backend.app.storage import (create_vault_metadata, delete_credential, get_encrypted_credential, get_vault_metadata, initialize_database, insert_credential, list_encrypted_credentials,update_credential,)
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="VaultGuard API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

SESSION_TTL_SECONDS = 15 * 60
VERIFIER_AAD = b"VaultGuard:verifier:v1"
ENTRY_AAD_PREFIX = b"VaultGuard:entry:v1:"
_sessions = {}
_sessions_lock = RLock()

class MasterPasswordRequest(BaseModel):
    master_password: str = Field(min_length=12, max_length=1024)

class CredentialInput(BaseModel):
    site: str = Field(min_length=1, max_length=200)
    username: str = Field(max_length=300)
    password: str = Field(min_length=1, max_length=4096)
    notes: str = Field(default="", max_length=4000)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def entry_aad(credential_id: str) -> bytes:
    return ENTRY_AAD_PREFIX + credential_id.encode("utf-8")

def make_verifier(key: bytes) -> str:
    envelope = encrypt_bytes(b"VaultGuard master password verification v1", key,aad=VERIFIER_AAD,)
    return json.dumps(envelope)

def verify_master_password(verifier: str, key: bytes) -> bool:
    try:
        plaintext = decrypt_bytes(json.loads(verifier),key,aad=VERIFIER_AAD,)
        return plaintext == b"VaultGuard master password verification v1"
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False

def issue_session(key: bytes) -> str:
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = {
            "key": key,
            "last_seen": time.monotonic(),
        }
    return token

bearer_scheme = HTTPBearer(scheme_name="VaultGuardSession", description="Enter the session token returned by POST /vault/unlock.", auto_error=False,)

def require_key(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),) -> bytes:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Vault is locked", headers={"WWW-Authenticate": "Bearer"},)

    token = credentials.credentials
    with _sessions_lock:
        session = _sessions.get(token)
        if session is None:
            raise HTTPException(status_code=401, detail="Invalid session", headers={"WWW-Authenticate": "Bearer"},)
        elapsed = time.monotonic() - session["last_seen"]
        if elapsed >= SESSION_TTL_SECONDS:
            _sessions.pop(token, None)
            raise HTTPException(status_code=401, detail="Session expired",headers={"WWW-Authenticate": "Bearer"},)
        session["last_seen"] = time.monotonic()
        return session["key"]

KeyDependency = Annotated[bytes, Depends(require_key)]

@app.on_event("startup")
def startup():
    initialize_database()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/vault/status")
def vault_status():
    metadata = get_vault_metadata()
    return {"exists": metadata is not None}

@app.post("/vault/setup", status_code=201)
def setup_vault(body: MasterPasswordRequest):
    if get_vault_metadata() is not None:
        raise HTTPException(status_code=409, detail="Vault already exists",)
    salt = generate_salt()
    key = derive_key(body.master_password, salt)
    verifier = make_verifier(key)

    try:
        create_vault_metadata(salt, verifier)
    except Exception:
        raise HTTPException(status_code=409, detail="Could not create vault; it may already exist",)
    return {"message": "Vault created. Unlock it to begin."}

@app.post("/vault/unlock")
def unlock_vault(body: MasterPasswordRequest):
    metadata = get_vault_metadata()
    if metadata is None:
        raise HTTPException(status_code=404, detail="Vault has not been created",)
    key = derive_key(body.master_password, bytes(metadata["salt"]))
    if not verify_master_password(metadata["verifier"], key):
        raise HTTPException(status_code=401, detail="Incorrect master password",)
    return {
        "access_token": issue_session(key),
        "token_type": "bearer",
        "expires_in": SESSION_TTL_SECONDS,
    }

@app.post("/vault/lock")
def lock_vault(authorization: Annotated[str | None, Header()] = None,):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        with _sessions_lock:
            _sessions.pop(token, None)
    return {"message": "Vault locked"}

@app.get("/credentials")
def list_credentials(key: KeyDependency):
    result = []
    for row in list_encrypted_credentials():
        credential_id = row["id"]
        envelope = {
            "version": 1,
            "nonce": row["nonce"],
            "ciphertext": row["ciphertext"],
        }
        try:
            plaintext = decrypt_bytes(envelope, key, aad=entry_aad(credential_id))
            credential = json.loads(plaintext)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            raise HTTPException(status_code=500, detail="A stored credential could not be verified",)

        result.append({
            "id": credential_id,
            **credential,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return result

@app.post("/credentials", status_code=201)
def create_credential(body: CredentialInput, key: KeyDependency):
    credential_id = str(uuid.uuid4())
    timestamp = now_iso()
    plaintext = json.dumps(body.model_dump(), ensure_ascii=False, separators=(",", ":"),).encode("utf-8")
    envelope = encrypt_bytes(plaintext, key, aad=entry_aad(credential_id))
    insert_credential(credential_id=credential_id, nonce=envelope["nonce"], ciphertext=envelope["ciphertext"], timestamp=timestamp,)
    return {"id": credential_id, "message": "Credential saved"}

@app.put("/credentials/{credential_id}")
def edit_credential(credential_id: str, body: CredentialInput, key: KeyDependency,):
    if get_encrypted_credential(credential_id) is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    plaintext = json.dumps(body.model_dump(), ensure_ascii=False, separators=(",", ":"),).encode("utf-8")
    envelope = encrypt_bytes(plaintext, key, aad=entry_aad(credential_id))
    updated = update_credential(credential_id, envelope["nonce"], envelope["ciphertext"], now_iso(),)
    if not updated:
        raise HTTPException(status_code=404, detail="Credential not found")
    return {"message": "Credential updated"}

@app.delete("/credentials/{credential_id}", status_code=204)
def remove_credential(credential_id: str, key: KeyDependency):
    if not delete_credential(credential_id):
        raise HTTPException(status_code=404, detail="Credential not found")
    return None