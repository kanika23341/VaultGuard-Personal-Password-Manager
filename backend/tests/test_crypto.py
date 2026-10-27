import pytest
from backend.app.crypto import(decrypt_bytes, derive_key, encrypt_bytes, generate_salt)

def make_key(password="test-mpass"):
    salt=generate_salt()
    return derive_key(password,salt)

def test_encryption_round_trip():
    key=make_key()
    secret=b"test.com|kanika|fake-pass"
    envelope=encrypt_bytes(secret,key)
    assert decrypt_bytes(envelope,key)==secret
    assert secret.decode() not in str(envelope)

def test_each_encryption_uses_diff_nonce():
    key=make_key()
    first=encrypt_bytes(b"same",key)
    second=encrypt_bytes(b"same",key)
    assert first["nonce"]!=second["nonce"]
    assert first["ciphertext"]!=second["ciphertext"]

def test_wrong_key():
    crctKey=make_key("correct")
    wrongKey=make_key("wrong")
    envelope=encrypt_bytes(b"private infos", crctKey)
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_bytes(envelope, wrongKey)

def test_modified_ciphertext():
    key=make_key()
    Envelope=encrypt_bytes(b"private info",key)
    mod=Envelope.copy()
    ciphertext=bytearray(
        __import__("base64").b64decode(mod["ciphertext"])
    )
    ciphertext[0]^=1
    mod["ciphertext"]=__import__("base64").b64encode(ciphertext).decode("ascii")
    with pytest.raises(ValueError):
        decrypt_bytes(mod,key)

def test_diff_salts_same_pass():
    salt_a=generate_salt()
    salt_b=generate_salt()
    key_a=derive_key("same-mpass",salt_a)
    key_b=derive_key("same-mpass",salt_b)
    assert salt_a!=salt_b
    assert key_a!=key_b

def test_empty_mpass():
    with pytest.raises(ValueError):
        derive_key("",generate_salt())

def test_wrong_keyLength():
    with pytest.raises(ValueError):
        encrypt_bytes(b"secret",b"toosmall")

def test_unsuported_envelopeVersion():
    key=make_key()
    with pytest.raises(ValueError, match="Unsupported"):
        decrypt_bytes({"version":2},key)