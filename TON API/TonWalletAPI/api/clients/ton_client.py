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
            if getattr(settings, 'USE_TESTNET', False)
            else 'https://ton.org/global.config.json'
        )
        self.ton_config = requests.get(cfg_url).json()

        # Pasta para armazenar chaves temporárias
        ks = getattr(settings, 'TONLIB_KEYSTORE', '/tmp/ton_keystore')
        Path(ks).mkdir(parents=True, exist_ok=True)
        self.keystore = ks
        # Timeout padrão em ms
        self.tonlib_timeout = getattr(settings, 'TONLIB_TIMEOUT', 30000)

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

    def get_account_balance(self, address: str) -> float:
        """Consulta o saldo de `address` via raw_run_method e retorna em TON."""
        async def _():
            client = await self._get_client()
            res = await client.raw_run_method(
                address,
                'get_account_state',
                []
            )
            await client.close()
            # raw_run_method pode retornar JSON-RPC ou runResult direto
            data = res.get('result', res)
            # Caso response seja um objeto de estado de conta
            if isinstance(data, dict) and 'balance' in data and 'coins' in data['balance']:
                return int(data['balance']['coins']) / 1e9
            # Caso runResult para contas não inicializadas ou estado
            if data.get('@type') == 'smc.runResult':
                stack = data.get('stack', [])
                # espera [['num', '0x...']]
                if stack and stack[0][0] == 'num':
                    coins = int(stack[0][1], 16)
                    return coins / 1e9
                # senão não conseguiu extrair
                raise Exception(f"Não foi possível extrair coins de runResult: {data}")
            # formato inesperado
            raise Exception(f"Formato inesperado na resposta: {data}")
        # Antes: return self.run_async(_())(_())
        # Correção: apenas executar a coroutine
        return self.run_async(_())
