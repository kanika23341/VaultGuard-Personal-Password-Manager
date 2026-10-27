import pytest
from fastapi.testclient import TestClient
from backend.app import api

@pytest.fixture
def client(tmp_path, monkeypatch):
    from backend.app import storage
    test_db = tmp_path / "test_vault.db"
    monkeypatch.setattr(storage, "dbPath", test_db)
    monkeypatch.setattr(storage, "dataDir", tmp_path)
    monkeypatch.setattr(api, "initialize_database", lambda: None)
    storage.initialize_database()
    api._sessions.clear()
    with TestClient(api.app) as test_client:
        yield test_client
    api._sessions.clear()

@pytest.fixture
def unlocked_client(client):
    password = "TestMasterPassword!123"
    response = client.post("/vault/setup", json={"master_password": password},)
    assert response.status_code == 201, response.text
    response = client.post("/vault/unlock", json={"master_password": password},)
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200

def test_setup_rejects_second_vault_setup(client):
    payload = {"master_password": "TestMasterPassword!123"}
    first = client.post("/vault/setup", json=payload)
    second = client.post("/vault/setup", json=payload)
    assert first.status_code == 201
    assert second.status_code == 409

def test_wrong_master_password_is_rejected(client):
    client.post("/vault/setup", json={"master_password": "TestMasterPassword!123"},)
    response = client.post("/vault/unlock", json={"master_password": "WrongPassword!456"},)
    assert response.status_code in (401, 403)

def test_credentials_require_authentication(client):
    response = client.get("/credentials")
    assert response.status_code in (401, 403)

def test_create_and_list_credential(unlocked_client):
    payload = {
        "site": "Example account",
        "username": "demo_user",
        "password": "dummy-only-password",
        "url": "https://example.com",
        "notes": "Automated test entry",
    }
    created = unlocked_client.post("/credentials", json=payload)
    assert created.status_code in (200, 201), created.text
    listed = unlocked_client.get("/credentials")
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert len(body) == 1
    assert "id" in body[0]

def test_lock_invalidates_session(unlocked_client):
    response = unlocked_client.post("/vault/lock")
    assert response.status_code == 200, response.text
    response = unlocked_client.get("/credentials")
    assert response.status_code in (401, 403)

def test_credentials_are_encrypted_at_rest(unlocked_client):
    import sqlite3
    from backend.app.storage import dbPath
    payload = {
        "site": "Encryption Test Account",
        "username": "vault_test_user",
        "password": "dummy-secret-12345",
        "url": "https://example.com",
        "notes": "Test encryption only",
    }
    created = unlocked_client.post("/credentials", json=payload)
    assert created.status_code in (200, 201), created.text
    with sqlite3.connect(dbPath) as connection: 
        rows = connection.execute("SELECT nonce, ciphertext FROM credentials").fetchall()
    assert len(rows) == 1
    raw_data = str(rows[0])
    assert "dummy-secret-12345" not in raw_data
    assert "vault_test_user" not in raw_data
    assert "Encryption Test Account" not in raw_data


def test_tampered_ciphertext_is_rejected(unlocked_client, monkeypatch):
    import backend.app.api as api
    from backend.app import storage
    payload = {
        "site": "Tamper Test",
        "username": "dummy_user",
        "password": "dummy-secret-12345",
        "url": "https://example.com",
        "notes": "Test only",
    }
    created = unlocked_client.post("/credentials", json=payload)
    assert created.status_code in (200, 201), created.text
    rows = storage.list_encrypted_credentials()
    assert len(rows) == 1
    row = rows[0]
    original_ciphertext = row["ciphertext"]
    replacement = ("A" if original_ciphertext[0] != "A" else "B")
    tampered_ciphertext = replacement + original_ciphertext[1:]
    assert storage.update_credential(
        row["id"],
        row["nonce"],
        tampered_ciphertext,
        row["updated_at"],
    )
    response = unlocked_client.get("/credentials")
    assert response.status_code == 500
    assert response.json()["detail"] == (
        "A stored credential could not be verified"
    )

def test_expired_session_is_rejected(unlocked_client, monkeypatch):
    import backend.app.api as api
    token = unlocked_client.headers["Authorization"].split(" ", 1)[1]
    session = api._sessions[token]
    session["last_seen"] -= api.SESSION_TTL_SECONDS + 1
    response = unlocked_client.get("/credentials")
    assert response.status_code in (401, 403)

def test_update_credential(unlocked_client):
    payload = {
        "site": "Example",
        "username": "old_user",
        "password": "old-secret-123",
        "url": "https://example.com",
        "notes": "Original notes",
    }
    created = unlocked_client.post("/credentials", json=payload)
    assert created.status_code in (200, 201), created.text
    credential_id = created.json()["id"]
    updated_payload = {
        "site": "Updated Example",
        "username": "new_user",
        "password": "new-secret-456",
        "url": "https://example.com",
        "notes": "Updated notes",
    }
    response = unlocked_client.put(f"/credentials/{credential_id}", json=updated_payload,)
    assert response.status_code == 200, response.text
    listed = unlocked_client.get("/credentials")
    assert listed.status_code == 200, listed.text
    credential = next(item for item in listed.json() if item["id"] == credential_id)
    assert credential["site"] == "Updated Example"
    assert credential["username"] == "new_user"
    assert credential["password"] == "new-secret-456"
