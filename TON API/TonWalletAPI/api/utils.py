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

from tonsdk.contract.wallet import Wallets, WalletVersionEnum
from tonsdk.crypto import (
    mnemonic_new,
    mnemonic_to_wallet_key,
    mnemonic_is_valid,
)

logger = logging.getLogger(__name__)

# Configurações
CRYPTO_ITERATIONS = 600_000

class BlockchainError(Exception):
    """Exceção genérica para erros relacionados à blockchain."""
    pass

# ======= GERAÇÃO E VALIDAÇÃO DE SEED =======

def generate_seed_phrase(words_count: int = 24) -> list[str]:
    """Gera uma nova seed phrase com o número especificado de palavras."""
    if words_count not in (12, 15, 18, 24):
        raise ValueError("words_count deve ser 12, 15, 18 ou 24")
    return mnemonic_new(words_count=words_count)


def validate_seed_phrase(phrase: str) -> bool:
    """Valida se a phrase fornecida é uma seed válida."""
    words = phrase.strip().split()
    return mnemonic_is_valid(words)

# ======= CRIPTOGRAFIA LOCAL =======

@lru_cache(maxsize=1)
def derive_crypto_key() -> bytes:
    """Deriva uma chave simétrica para criptografia local a partir de settings.SECRET_KEY."""
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
    """Encripta a seed phrase para armazenamento seguro."""
    cipher = Fernet(derive_crypto_key())
    return cipher.encrypt(seed.encode()).decode()


def decrypt_seed(encrypted: str) -> str:
    """Desencripta a seed armazenada, lançando BlockchainError em caso de falha."""
    cipher = Fernet(derive_crypto_key())
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        raise BlockchainError("Token de descriptografia inválido.")
    except Exception as e:
        logger.exception("Erro inesperado na descriptografia: %s", e)
        raise BlockchainError("Erro interno na descriptografia.")

# ======= DERIVAÇÃO DE CHAVES E ENDEREÇO =======

def derive_keys_and_address(seed_phrase: str, workchain: int = 0) -> dict[str, str]:
    """Deriva chaves pública/privada e endereço a partir de uma seed phrase."""
    words = seed_phrase.strip().split()
    logger.debug("Iniciando derivação com words=%s", words)

    try:
        # Utiliza o helper do SDK para derivar chaves e instanciar a carteira
        _, public_key, private_key, wallet = Wallets.from_mnemonics(
            mnemonics=words,
            version=WalletVersionEnum.v4r2,
            workchain=workchain
        )
        address = wallet.address.to_string(
            is_bounceable=True,
            is_test_only=(workchain != 0),
            is_user_friendly=True
        )
        logger.debug(
            "Chaves derivadas public_key=%s private_key=%s address=%s",
            public_key.hex(), private_key.hex(), address
        )
        return {
            "public_key": public_key.hex(),
            "private_key": private_key.hex(),
            "address": address
        }
    except Exception:
        logger.exception("Falha completa na derive_keys_and_address")
        raise BlockchainError("Erro ao derivar chaves e endereço.")

# ======= ASSINATURA =======

def sign_transaction(seed_phrase: str, payload: dict) -> bytes:
    """Assina um payload JSON usando a chave derivada da seed phrase."""
    words = seed_phrase.strip().split()
    if not mnemonic_is_valid(words):
        raise BlockchainError("Seed phrase inválida para assinatura.")

    try:
        public_key, private_key = mnemonic_to_wallet_key(words)
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        data = json.dumps(payload, separators=(',', ':')).encode()
        signature = private_key_obj.sign(data)
        logger.debug("Payload assinado signature=%s", signature.hex())
        return signature
    except Exception:
        logger.exception("Falha ao assinar payload")
        raise BlockchainError("Erro na assinatura de payload.")

# ======= BROADCAST =======

def broadcast_transaction(tx_data: dict, signature: bytes) -> dict:
    """Envia a transação para um nó TON via JSON-RPC e retorna o resultado."""
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
        logger.debug("Broadcast bem-sucedido result=%s", data.get("result"))
        return data.get("result", {})
    except requests.Timeout:
        logger.exception("Timeout ao tentar broadcastar transação.")
        raise BlockchainError("Timeout ao enviar transação.")
    except requests.RequestException:
        logger.exception("Erro HTTP ao enviar transação")
        raise BlockchainError("Falha de conexão ao broadcast.")
    except Exception:
        logger.exception("Erro inesperado no broadcast")
        raise BlockchainError("Erro interno no broadcast.")
