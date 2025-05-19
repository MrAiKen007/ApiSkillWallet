# ton_client.py
from tonsdk.client import TonClient
from django.conf import settings


def get_ton_client() -> TonClient:
    """
    Retorna uma instância do TonClient, com base no modo testnet/mainnet
    e usando o nó customizado definido nas configurações.
    """
    # Usa URL da testnet se USE_TESTNET for True, senão usa o da mainnet
    default_url = settings.TONCENTER_RPC_URL if settings.USE_TESTNET else settings.TON_NODE_URL

    # Permite sobrescrever com um nó customizado
    base_url = settings.TON_NODE_URL or default_url

    return TonClient(base_url=base_url)