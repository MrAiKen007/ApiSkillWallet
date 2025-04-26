import base64
import hashlib
import json
import logging
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from mnemonic import Mnemonic
from tonsdk.contract.wallet import Wallets, WalletVersionEnum

logger = logging.getLogger(__name__)

class BlockchainError(Exception):
    pass

# Configuração de segurança
CRYPTO_ITERATIONS = 600_000  # OWASP recomenda ≥100k iterações

# Geração e validação de seed phrase (BIP-39)
def generate_seed_phrase(strength: int = 256) -> str:
    """Gera uma seed phrase BIP-39 segura (24 palavras)."""
    return Mnemonic("english").generate(strength=strength)

def validate_seed_phrase(phrase: str) -> bool:
    """Valida uma seed phrase usando padrão BIP-39."""
    return Mnemonic("english").check(phrase)

# Criptografia da seed com Fernet
def derive_crypto_key() -> bytes:
    """Deriva chave para Fernet usando SECRET_KEY e CRYPTO_SALT."""
    salt = settings.CRYPTO_SALT
    if isinstance(salt, str):
        salt = salt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
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

# Derivação offline de chave pública e endereço usando tonsdk
def derive_keys_and_address(seed_phrase: str):
    """
    A partir da seed phrase (24 palavras), retorna:
      - public_key (hex, 64 chars)
      - contract_address (bounceable, user-friendly)
    100% offline, sem chamadas externas.
    """
    words = seed_phrase.split()
    version = WalletVersionEnum.v3r2  # ou v4
    workchain = 0  # mainnet (use -1 para testnet se necessário)

    # Gera pubkey_bytes e o objeto wallet
    _, pubkey_bytes, _, wallet_obj = Wallets.from_mnemonics(
        words, version, workchain
    )
    public_key_hex = pubkey_bytes.hex()
    address = wallet_obj.address.to_string(
        bounceable=True,
        test_only=(workchain != 0),
        user_friendly=True
    )
    return public_key_hex, address

# Assinatura de transação
def sign_transaction(seed: str, data: dict) -> bytes:
    """Assina digitalmente um payload JSON com Ed25519."""
    priv = hashlib.sha256(seed.encode()).digest()
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
    return private_key.sign(json.dumps(data).encode())

# Broadcast opcional se tiver nó local configurado
def broadcast_transaction(tx_data: dict, signature: bytes) -> dict:
    """
    Envia transação para nó local configurado em settings.TON_NODE_URL.
    """
    rpc_url = getattr(settings, "TON_NODE_URL", None)
    if not rpc_url:
        raise BlockchainError("TON_NODE_URL não configurado para broadcast")
    headers = {"Content-Type": "application/json"}
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
