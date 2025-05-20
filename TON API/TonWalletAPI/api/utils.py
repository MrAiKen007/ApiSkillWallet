import base64
import json
import logging
import requests
from functools import lru_cache
from pathlib import Path

from django.conf import settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

from .clients.ton_client import PyTONClient
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
    """Deriva chaves pública/privada e retorna a public_key/secret e o endereço user-friendly."""
    words = seed_phrase.strip().split()
    if not mnemonic_is_valid(words):
        raise BlockchainError("Seed phrase inválida.")
    pubkey, privkey = mnemonic_to_wallet_key(words)
    return {
        "public_key": pubkey.hex(),
        "private_key": privkey.hex(),
    }


# ======= BLOCKCHAIN OPERATIONS via PyTONClient =======

def get_account_balance(address: str) -> float:
    """Consulta o saldo de `address` via PyTONClient (retorna em TON)."""
    client = PyTONClient()
    try:
        return client.get_account_balance(address)
    except Exception as e:
        logger.exception("Erro ao obter saldo: %s", e)
        raise BlockchainError("Não foi possível obter saldo.")


def sign_transaction(from_address: str, to_address: str, amount: float, seed_phrase: str) -> str:
    """
    Prepara e assina a transação, retornando a mensagem assinada (BOC base64).
    """
    keys = derive_keys_and_address(seed_phrase)
    client = PyTONClient()
    try:
        # Ajuste para o método correto de assinatura no seu cliente
        signed_boc = client.sign_message(from_address, to_address, amount, keys['private_key'])
        return signed_boc
    except Exception as e:
        logger.exception("Erro ao assinar transação: %s", e)
        raise BlockchainError("Falha ao assinar transação.")


def broadcast_transaction(signed_boc: str) -> str:
    """
    Envia (broadcast) a mensagem BOC assinada para a rede, retornando o hash da transação.
    """
    client = PyTONClient()
    try:
        # Ajuste para o método correto de broadcast no seu cliente
        tx_hash = client.broadcast_message(signed_boc)
        return tx_hash
    except Exception as e:
        logger.exception("Erro ao broadcast da transação: %s", e)
        raise BlockchainError("Falha ao broadcast da transação.")


def send_ton(from_address: str, to_address: str, amount: float, seed_phrase: str) -> str:
    """
    Assina e envia `amount` TON de from_address para to_address.
    Retorna o hash da transação.
    """
    signed = sign_transaction(from_address, to_address, amount, seed_phrase)
    return broadcast_transaction(signed)