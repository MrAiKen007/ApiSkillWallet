import base64
import json
import hashlib
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from django.conf import settings
from mnemonic import Mnemonic
from cryptography.fernet import Fernet

class BlockchainError(Exception):
    pass

# Configuração de segurança
CRYPTO_ITERATIONS = 600_000  # Número recomendado pelo OWASP para PBKDF2

def generate_seed_phrase(strength=256):
    """Gera uma seed phrase BIP-39 segura (24 palavras)"""
    return Mnemonic("english").generate(strength=strength)

def validate_seed_phrase(phrase):
    """Valida uma seed phrase usando padrão BIP-39"""
    return Mnemonic("english").check(phrase)

def derive_crypto_key():
    """Deriva chave criptográfica usando SECRET_KEY e CRYPTO_SALT"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=settings.CRYPTO_SALT,
        iterations=CRYPTO_ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(
        kdf.derive(settings.SECRET_KEY.encode())
    )

def encrypt_seed(seed: str) -> str:
    """Criptografa a seed phrase usando chave derivada"""
    cipher = Fernet(derive_crypto_key())
    return cipher.encrypt(seed.encode()).decode()

def decrypt_seed(encrypted: str) -> str:
    """Descriptografa a seed phrase usando chave derivada"""
    try:
        cipher = Fernet(derive_crypto_key())
        return cipher.decrypt(encrypted.encode()).decode()
    except Exception as e:
        raise BlockchainError(f"Falha na descriptografia: {str(e)}")

def get_public_key(seed: str) -> str:
    """Gera chave pública Ed25519 a partir da seed"""
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(seed.encode()).digest()
    )
    return private_key.public_key().public_bytes_raw().hex()

def sign_transaction(seed: str, data: dict) -> bytes:
    """Cria assinatura digital para transações"""
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(seed.encode()).digest()
    )
    return private_key.sign(json.dumps(data).encode())

def broadcast_transaction(tx_data: dict, signature: bytes) -> dict:
    """Envia transação para a rede TON"""
    headers = {
        'Authorization': f'Bearer {settings.TON_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            f"{settings.TON_NODE_URL}/transactions",
            json={
                'transaction': tx_data,
                'signature': signature.hex()
            },
            headers=headers,
            timeout=15
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise BlockchainError(f"Erro na rede: {e}")
    
def derive_fernet_key(secret: str = None, salt: bytes = None) -> bytes:
    """Deriva chave Fernet (permite usar chaves antigas)"""
    secret = secret or settings.SECRET_KEY
    salt = salt or settings.CRYPTO_SALT
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=600000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))