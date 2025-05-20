import requests
from pathlib import Path
from pytonlib import TonlibClient
import asyncio
from django.conf import settings

class PyTONClient:
    def __init__(self):
        # Escolhe config de testnet ou mainnet
        cfg_url = (
            'https://ton-blockchain.github.io/testnet-global.config.json'
            if settings.USE_TESTNET
            else 'https://ton.org/global.config.json'
        )
        self.ton_config = requests.get(cfg_url).json()

        # Pasta para armazenar chaves temporárias
        ks = getattr(settings, 'TONLIB_KEYSTORE', '/tmp/ton_keystore')
        Path(ks).mkdir(parents=True, exist_ok=True)
        self.keystore = ks

    async def _get_client(self):
        client = TonlibClient(
            ls_index=0,
            config=self.ton_config,
            keystore=self.keystore
        )
        await client.init()
        return client

    def run_async(self, coro):
        return asyncio.run(coro)

    def get_masterchain_info(self):
        async def _():
            client = await self._get_client()
            info = await client.get_masterchain_info()
            await client.close()
            return info
        return self.run_async(_())

    def get_account_balance(self, address: str):
        async def _():
            client = await self._get_client()
            res = await client.raw_run_method(
                address, 'get_account_state', []
            )
            await client.close()
            # Extrai balance: res['balance']['coins']
            return int(res['balance']['coins']) / 1e9
        return self.run_async(_())