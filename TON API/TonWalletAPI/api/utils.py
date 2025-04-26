import base64
import json
import logging
import requests

from django.conf import settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from mnemonic import Mnemonic

# Tentativa de import do TonWallet; suprimir erro do Pylance se não estiver no ambiente.
try:
    from tonpy import TonWallet  # type: ignore
except ImportError:
    TonWallet = None  # type: ignore

from tonsdk.contract.wallet import Wallets, WalletVersionEnum
from tonsdk.crypto.exceptions import InvalidMnemonicsError

logger = logging.getLogger(__name__)

class BlockchainError(Exception):
    """Exceção genérica para erros de blockchain"""
    pass

# Configurações
CRYPTO_ITERATIONS = 600_000  # OWASP recomenda ≥100k iterações

# ======= GERAÇÃO DE CARTEIRA =======
def create_wallet():
    """
    Gera uma nova carteira TON usando TonWallet (tonpy).
    Retorna:
        address (str): endereço público da carteira
        private_key (str): chave privada em hex
    """
    if TonWallet is None:
        raise BlockchainError("Biblioteca tonpy não está instalada. Instale com 'pip install tonpy'.")
    try:
        wallet = TonWallet()
        address = wallet.get_address()
        private_key = wallet.get_private_key()
        return address, private_key
    except Exception as e:
        logger.exception("Erro ao gerar carteira TON")
        raise BlockchainError(f"Falha ao gerar carteira TON: {e}")

# ======= SEED PHRASE =======
def generate_seed_phrase(strength: int = 256) -> str:
    """Gera uma seed phrase BIP-39 segura (24 palavras)."""
    return Mnemonic("english").generate(strength=strength)

def validate_seed_phrase(phrase: str) -> bool:
    """Valida uma seed phrase usando padrão BIP-39."""
    return Mnemonic("english").check(phrase)

# ======= CRIPTOGRAFIA =======
def derive_crypto_key() -> bytes:
    """Deriva chave para Fernet usando SECRET_KEY e CRYPTO_SALT."""
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
    """Criptografa a seed ou private key usando Fernet."""
    cipher = Fernet(derive_crypto_key())
    return cipher.encrypt(seed.encode()).decode()

def decrypt_seed(encrypted: str) -> str:
    """Descriptografa a seed ou private key."""
    cipher = Fernet(derive_crypto_key())
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except InvalidToken as e:
        logger.error("Falha na descriptografia (token inválido): %r", e)
        raise BlockchainError("Falha na descriptografia: token inválido")
    except Exception as e:
        logger.exception("Erro inesperado na descriptografia")
        raise BlockchainError("Falha na descriptografia: erro interno")

# ======= DERIVAÇÃO DE CHAVES =======
def derive_keys_and_address(seed_phrase: str, version: str = WalletVersionEnum.v4r2.value, workchain: int = 0):
    """Deriva a public key e endereço TON de uma seed phrase."""
    words = seed_phrase.strip().split()
    try:
        _, pubkey_bytes, _, wallet_obj = Wallets.from_mnemonics(words, version, workchain)
    except InvalidMnemonicsError:
        raise BlockchainError(
            "Seed phrase inválida para derivação offline. Por favor, verifique as 24 palavras."
        )
    except Exception as e:
        logger.error("Erro inesperado na derivação offline: %s", e)
        raise BlockchainError("Falha na derivação offline de endereço")

    public_key_hex = pubkey_bytes.hex()
    address = wallet_obj.address.to_string(
        bounceable=True,
        test_only=(workchain != 0),
        user_friendly=True
    )
    return public_key_hex, address

# ======= ASSINATURA =======
def sign_transaction(seed_phrase: str, payload: dict) -> bytes:
    """Assina payload JSON usando Ed25519 derivado da seed."""
    if not validate_seed_phrase(seed_phrase):
        raise BlockchainError("Seed phrase inválida para assinatura.")
    words = seed_phrase.strip().split()
    try:
        _, private_key_bytes, _, _ = Wallets.from_mnemonics(
            words,
            WalletVersionEnum.v4r2.value,
            0
        )
    except Exception as e:
        logger.error("Erro ao derivar chave privada para assinatura: %s", e)
        raise BlockchainError("Falha ao derivar chave privada para assinatura.")

    from cryptography.hazmat.primitives.asymmetric import ed25519
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    data = json.dumps(payload, separators=(',', ':')).encode()
    return private_key.sign(data)

# ======= BROADCAST =======
def broadcast_transaction(tx_data: dict, signature: bytes) -> dict:
    """Envia uma transação assinada para um nó via TON_NODE_URL."""
    rpc_url = getattr(settings, "TON_NODE_URL", None)
    if not rpc_url:
        raise BlockchainError("TON_NODE_URL não configurado para broadcast")

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
        resp = requests.post(rpc_url, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json().get("result", {})
    except requests.RequestException as e:
        logger.exception("Erro ao enviar transação para o nó.")
        raise BlockchainError(f"Erro ao broadcastar transação: {e}")
