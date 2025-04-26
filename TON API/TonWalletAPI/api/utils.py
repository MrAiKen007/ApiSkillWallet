import base64
import json
import logging
import requests
from functools import lru_cache

from django.conf import settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

from tonsdk.crypto.exceptions import InvalidMnemonicsError
from tonsdk.contract.wallet import WalletV4ContractR2
from tonsdk.crypto import (
    mnemonic_new,
    mnemonic_to_wallet_key,
    mnemonic_is_valid,
)
from tonsdk.utils import Address, bytes_to_b64str

logger = logging.getLogger(__name__)

# Configurações
CRYPTO_ITERATIONS = 600_000

class BlockchainError(Exception):
    """Exceção genérica para erros relacionados à blockchain."""
    pass

# ======= GERAÇÃO E VALIDAÇÃO DE SEED =======

def generate_seed_phrase(words_count: int = 24) -> list[str]:
    if words_count not in (12, 15, 18, 24):
        raise ValueError("words_count deve ser 12, 15, 18 ou 24")
    return mnemonic_new(words_count=words_count)

def validate_seed_phrase(phrase: str) -> bool:
    words = phrase.strip().split()
    return mnemonic_is_valid(words)  # Função corrigida

# ======= CRIPTOGRAFIA LOCAL =======

@lru_cache(maxsize=1)
def derive_crypto_key() -> bytes:
    salt = settings.CRYPTO_SALT.encode() if isinstance(settings.CRYPTO_SALT, str) else settings.CRYPTO_SALT
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=CRYPTO_ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(settings.SECRET_KEY.encode()))

def encrypt_seed(seed: str) -> str:
    cipher = Fernet(derive_crypto_key())
    return cipher.encrypt(seed.encode()).decode()

def decrypt_seed(encrypted: str) -> str:
    cipher = Fernet(derive_crypto_key())
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        raise BlockchainError("Token de descriptografia inválido.")
    except Exception as e:
        logger.exception("Erro inesperado na descriptografia: %s", e)
        raise BlockchainError("Erro interno na descriptografia.")

# ======= DERIVAÇÃO DE CHAVES =======

def derive_keys_and_address(seed_phrase: str, workchain: int = 0) -> dict[str, str]:
    words = seed_phrase.strip().split()
    try:
        public_key, private_key = mnemonic_to_wallet_key(words)
        wallet = WalletV4ContractR2(public_key=public_key, private_key=private_key, workchain=workchain)
        return {
            "private_key": private_key.hex(),
            "public_key": public_key.hex(),
            "address": wallet.address.to_string(
                 bounceable=True,
                 test_only=(workchain != 0),
                 user_friendly=True
       )
    }
    except InvalidMnemonicsError:
        raise BlockchainError("Seed phrase inválida.")
    except Exception as e:
        logger.error("Erro na derivação: %s", e)
        raise BlockchainError("Erro ao derivar chaves e endereço.")

# ======= ASSINATURA =======

def sign_transaction(seed_phrase: str, payload: dict) -> bytes:
    words = seed_phrase.strip().split()
    if not mnemonic_is_valid(words):  # Função corrigida
        raise BlockchainError("Seed phrase inválida para assinatura.")

    try:
        key_pair = mnemonic_to_wallet_key(words)
        from cryptography.hazmat.primitives.asymmetric import ed25519
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_pair.secret.key)
        data = json.dumps(payload, separators=(',', ':')).encode()
        return private_key.sign(data)
    except Exception as e:
        logger.error("Falha ao assinar payload: %s", e)
        raise BlockchainError("Erro na assinatura de payload.")

# ======= BROADCAST =======

def broadcast_transaction(tx_data: dict, signature: bytes) -> dict:
    rpc_url = getattr(settings, "TON_NODE_URL", None)
    if not rpc_url:
        raise BlockchainError("TON_NODE_URL não configurado.")

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
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(rpc_url, json=payload, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            logger.error("Erro do nó TON: %s", data["error"])
            raise BlockchainError(f"Erro do nó TON: {data['error']}")
        return data.get("result", {})
    except requests.Timeout:
        logger.exception("Timeout ao tentar broadcastar transação.")
        raise BlockchainError("Timeout ao enviar transação.")
    except requests.RequestException as e:
        logger.exception("Erro HTTP ao enviar transação: %s", e)
        raise BlockchainError(f"Falha de conexão: {e}")
    except Exception as e:
        logger.exception("Erro inesperado no broadcast: %s", e)
        raise BlockchainError("Erro interno no broadcast.")