import base64
import logging
from functools import lru_cache

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
from tonsdk.utils import Address  # Derivação de endereço correta

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


def decrypt_seed(encrypted: str, password: str = None) -> str:
    """Desencripta a seed armazenada."""
    try:
        if password:
            # Se tiver senha, usa ela para derivar a chave
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=settings.CRYPTO_SALT,
                iterations=CRYPTO_ITERATIONS,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            cipher = Fernet(key)
        else:
            # Se não tiver senha, usa a chave padrão
            cipher = Fernet(derive_crypto_key())
            
        return cipher.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        raise BlockchainError("Token de descriptografia inválido.")
    except Exception as e:
        logger.exception("Erro inesperado na descriptografia: %s", e)
        raise BlockchainError("Erro interno na descriptografia.")


# ======= DERIVAÇÃO DE CHAVES E ENDEREÇO =======

def derive_keys_and_address(seed_phrase: str, testnet: bool = False) -> dict[str, str]:
    """Deriva chaves pública, privada e endereço user-friendly."""
    from tonsdk.contract.wallet import Wallets, WalletVersionEnum
    from tonsdk.crypto import mnemonic_is_valid, mnemonic_to_wallet_key

    words = seed_phrase.strip().split()
    if not mnemonic_is_valid(words):
        raise BlockchainError("Seed phrase inválida.")

    # Deriva mnemonics, chaves e wallet
    _, pubkey_bytes, privkey_bytes, wallet = Wallets.from_mnemonics(
        words,
        WalletVersionEnum.v3r2,
        0  # workchain
    )

    # Gera o endereço com flags de testnet/mainnet
    address_str = wallet.address.to_string(
    is_user_friendly=True,
    is_url_safe=True,
    is_bounceable=False,
    is_test_only=True,
)

    return {
        "public_key": pubkey_bytes.hex(),
        "private_key": privkey_bytes.hex(),
        "address": address_str,
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
    """Assina transação e retorna BOC base64 assinado."""
    try:
        logging.info(f"Derivando chaves da seed phrase para endereço {from_address}")
        keys = derive_keys_and_address(seed_phrase)
        logging.info("Chaves derivadas com sucesso")
        
        client = PyTONClient()
        logging.info(f"Assinando transação: {from_address} -> {to_address} ({amount} nanoTON)")
        try:
            boc = client.sign_message(
                from_address=from_address,
                to_address=to_address,
                amount=amount,
                private_key=keys['private_key']
            )
            logging.info("Transação assinada com sucesso")
            return boc
        except Exception as e:
            logging.exception(f"Erro ao assinar mensagem: {str(e)}")
            raise BlockchainError(f"Falha ao assinar transação: {str(e)}")
    except Exception as e:
        logging.exception(f"Erro ao derivar chaves ou assinar transação: {str(e)}")
        raise BlockchainError(f"Falha ao assinar transação: {str(e)}")


def broadcast_transaction(signed_boc: str) -> str:
    """Envia o BOC assinado para a rede e retorna o hash da transação."""
    client = PyTONClient()
    try:
        return client.broadcast_message(signed_boc)
    except Exception as e:
        logger.exception("Erro ao broadcast da transação: %s", e)
        raise BlockchainError("Falha ao broadcast da transação.")


def send_ton(from_address: str, to_address: str, amount: float, seed_phrase: str) -> str:
    """Assina e envia transação, retornando o hash resultante."""
    signed_boc = sign_transaction(from_address, to_address, amount, seed_phrase)
    return broadcast_transaction(signed_boc)
