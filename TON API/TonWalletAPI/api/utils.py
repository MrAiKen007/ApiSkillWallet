import base64
import json
import hashlib
import requests
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from django.conf import settings
from mnemonic import Mnemonic

logger = logging.getLogger(__name__)

class BlockchainError(Exception):
    pass

# Configuração de segurança
CRYPTO_ITERATIONS = 600_000  # OWASP recomenda ≥100k iterações

def generate_seed_phrase(strength: int = 256) -> str:
    """Gera uma seed phrase BIP-39 segura (24 palavras)."""
    return Mnemonic("english").generate(strength=strength)

def validate_seed_phrase(phrase: str) -> bool:
    """Valida uma seed phrase usando padrão BIP-39."""
    return Mnemonic("english").check(phrase)

def derive_crypto_key() -> bytes:
    """Deriva chave para Fernet usando SECRET_KEY e CRYPTO_SALT."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=settings.CRYPTO_SALT.encode() if isinstance(settings.CRYPTO_SALT, str) else settings.CRYPTO_SALT,
        iterations=CRYPTO_ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(settings.SECRET_KEY.encode()))

def encrypt_seed(seed: str) -> str:
    """Criptografa a seed phrase usando Fernet."""
    cipher = Fernet(derive_crypto_key())
    return cipher.encrypt(seed.encode()).decode()

def decrypt_seed(encrypted: str) -> str:
    """Descriptografa a seed phrase."""
    cipher = Fernet(derive_crypto_key())
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except InvalidToken as e:
        logger.error("Falha na descriptografia (token inválido): %r", e)
        raise BlockchainError("Falha na descriptografia: token inválido")
    except Exception as e:
        logger.exception("Erro inesperado na descriptografia")
        raise BlockchainError("Falha na descriptografia: erro interno")

def get_public_key(seed: str) -> str:
    """Gera chave pública Ed25519 (hex 64 chars) a partir da seed."""
    priv = hashlib.sha256(seed.encode()).digest()
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
    return private_key.public_key().public_bytes_raw().hex()

def derive_ton_address_onchain(pubkey_hex: str) -> str:
    """
    Usa JSON-RPC do TONCenter (ou nó local) para derivar o address
    a partir da public key.
    Requer em settings:
      - TONCENTER_API_KEY
      - TONCENTER_RPC_URL (ex.: https://testnet.toncenter.com/api/v2/jsonRPC)
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAddressInformation",
        "params": {"publicKey": pubkey_hex}
    }
    headers = {"X-API-Key": settings.TONCENTER_API_KEY}
    resp = requests.post(settings.TONCENTER_RPC_URL, json=payload, headers=headers, timeout=15)
    resp.raise_for_status()
    result = resp.json().get("result") or {}
    address = result.get("address")
    if not address:
        raise BlockchainError("Endereço não retornado pelo nó TON")
    return address

def sign_transaction(seed: str, data: dict) -> bytes:
    """Assina digitalmente um payload JSON com Ed25519."""
    priv = hashlib.sha256(seed.encode()).digest()
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
    return private_key.sign(json.dumps(data).encode())

def broadcast_transaction(tx_data: dict, signature: bytes) -> dict:
    """
    Envia transação para seu nó TON ou serviço configurado em settings.TON_NODE_URL.
    Requer em settings:
      - TON_NODE_URL (ex.: http://127.0.0.1:6080/jsonRPC)
      - TONCENTER_API_KEY (caso o nó exija autenticação)
    """
    rpc_url = getattr(settings, "TON_NODE_URL", settings.TONCENTER_RPC_URL)
    headers = {
        "X-API-Key": settings.TONCENTER_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendMessage",
        "params": {
            "message": {
                "transaction": tx_data,
                "signature": signature.hex()
            }
        }
    }
    try:
        resp = requests.post(rpc_url, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json().get("result", {})
    except requests.RequestException as e:
        logger.exception("Erro ao broadcastar transação")
        raise BlockchainError(f"Erro na rede: {e}")
