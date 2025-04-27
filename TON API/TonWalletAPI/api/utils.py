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

from tonsdk.utils import Address
from tonsdk.contract.wallet import Wallets, WalletVersionEnum
from tonsdk.crypto import (
    mnemonic_new,
    mnemonic_to_wallet_key,
    mnemonic_is_valid,
)

logger = logging.getLogger(__name__)


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
    """Deriva uma chave simétrica para criptografia local."""
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
    """Desencripta a seed armazenada."""
    cipher = Fernet(derive_crypto_key())
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        raise BlockchainError("Token de descriptografia inválido.")
    except Exception as e:
        logger.exception("Erro inesperado na descriptografia: %s", e)
        raise BlockchainError("Erro interno na descriptografia.")

# ======= DERIVAÇÃO DE CHAVES E ENDEREÇO =======

def derive_keys_and_address(seed_phrase: str) -> dict[str, str]:
    """Deriva chaves pública/privada e endereço."""
    words = seed_phrase.strip().split()
    
    # Configuração dinâmica
    workchain = -1 if getattr(settings, 'USE_TESTNET', False) else 0
    is_testnet = workchain != 0

    try:
        # Criação da carteira
        _, public_key, private_key, wallet = Wallets.from_mnemonics(
            mnemonics=words,
            version=WalletVersionEnum.v4r2,
            workchain=workchain
        )

        # Geração do endereço no formato 0QD...
        address = wallet.address.to_string(
        is_user_friendly=True,
        is_bounceable=True,
        is_url_safe=True,
        is_test_only=is_testnet
    )

        return {
            "public_key": public_key.hex(),
            "private_key": private_key.hex(),
            "address": address
        }
    except Exception as e:
        logger.error(f"Falha na derivação: {str(e)}")
        raise BlockchainError("Erro na geração do endereço")

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
        return signature
    except Exception:
        logger.exception("Falha ao assinar payload")
        raise BlockchainError("Erro na assinatura de payload.")

# ======= BROADCAST =======

def broadcast_transaction(tx_data: dict, signature: bytes) -> dict:
    """Envia a transação para um nó TON."""
    rpc_url = (
        settings.TON_NODE_URL 
        if getattr(settings, 'USE_TESTNET', False) 
        else settings.TON_MAINNET_NODE_URL
    )
    
    headers = {"Content-Type": "application/json"}
    if hasattr(settings, 'TONCENTER_API_KEY'):
        headers["X-API-Key"] = settings.TONCENTER_API_KEY

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
    except requests.RequestException:
        logger.exception("Erro HTTP ao enviar transação")
        raise BlockchainError("Falha de conexão ao broadcast.")
    except Exception:
        logger.exception("Erro inesperado no broadcast")
        raise BlockchainError("Erro interno no broadcast.")