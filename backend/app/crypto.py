import base64
import os
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD=b"PasswordManager:v1"
saltLength=16
keyLength=32
nonceLength=12
a2TimeCost=3
a2MemoryCost=65536
a2Parallelism=2

def generate_salt()->bytes:
    return os.urandom(saltLength)

def derive_key(mpass: str, salt: bytes)->bytes:
    if not isinstance(mpass,str) or not mpass:
        raise ValueError("Master password must not be empty")
    if not isinstance(salt, bytes) or len(salt)!=saltLength:
        raise ValueError("Salt must be exactly 16 bytes")
    return hash_secret_raw(
        secret=mpass.encode("utf-8"),
        salt=salt,
        time_cost=a2TimeCost,
        memory_cost=a2MemoryCost,
        parallelism=a2Parallelism,
        hash_len=keyLength,
        type=Type.ID,
    )

def encrypt_bytes(plaintext: bytes, key:bytes, aad: bytes=AAD)->dict:
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes")
    if not isinstance(key,bytes) or len(key)!=keyLength:
        raise ValueError("Encryption key must be 32 bytes")
    nonce=os.urandom(nonceLength)
    ciphertext=AESGCM(key).encrypt(nonce,plaintext,aad)
    return{
        "version":1,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext":base64.b64encode(ciphertext).decode("ascii"),
    }
def decrypt_bytes(envelope: dict, key: bytes, aad: bytes=AAD)->bytes:
    if not isinstance(key,bytes) or len(key)!=keyLength:
        raise ValueError("Encryption key must be 32 bytes")
    if not isinstance(envelope,dict) or envelope.get("version")!=1:
        raise ValueError("Unsupported encrypted envelope")
    try:
        nonce=base64.b64decode(envelope["nonce"],validate=True)
        ciphertext=base64.b64decode(envelope["ciphertext"], validate=True)
    except(KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid encrypted envelope") from exc
    if len(nonce)!=nonceLength:
        raise ValueError("Invalid nonce length")
    try:
        return AESGCM(key).decrypt(nonce,ciphertext,aad)
    except InvalidTag as exc:
        raise ValueError("Decryption failed: incorrect key or modified data") from exc