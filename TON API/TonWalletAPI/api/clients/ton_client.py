import requests
from pathlib import Path
from pytonlib import TonlibClient
import asyncio
from tonsdk.utils import Address
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class PyTONClient:
    def __init__(self):
        self._ensure_testnet_config()
        self._setup_keystore()
        
    def _ensure_testnet_config(self):
        """Garante o uso da configuração da testnet"""
        self.ton_config = requests.get(
            'https://ton-blockchain.github.io/testnet-global.config.json'
        ).json()
        logger.debug("Configuração da testnet carregada")

    def _setup_keystore(self):
        """Configura o armazenamento de chaves"""
        self.keystore = getattr(settings, 'TONLIB_KEYSTORE', '/tmp/ton_keystore')
        Path(self.keystore).mkdir(parents=True, exist_ok=True)
        self.tonlib_timeout = getattr(settings, 'TONLIB_TIMEOUT', 30000)
        logger.debug(f"Keystore configurado em: {self.keystore}")

    async def _get_client(self):
        """Cria e inicializa o cliente Tonlib"""
        client = TonlibClient(
            ls_index=0,
            config=self.ton_config,
            keystore=self.keystore
        )
        await client.init()
        logger.debug("Cliente Tonlib inicializado")
        return client

    def get_account_balance(self, address: str) -> float:
        """Obtém o saldo mantendo o formato 0Q... com verificação completa"""
        async def _wrapper():
            client = None
            try:
                # Validação rigorosa do endereço
                validated_addr = self._validate_address(address)
                
                # Execução da consulta
                async with self._get_client() as client:
                    result = await client.raw_run_method(
                        validated_addr,
                        'get_wallet_data',
                        []
                    )
                    return self._parse_balance(result)
                    
            except Exception as e:
                logger.error(f"Falha na consulta: {str(e)}")
                return 0.0

        return asyncio.run(_wrapper())

    def _validate_address(self, address: str) -> str:
        """Valida e normaliza o endereço no formato 0Q..."""
        try:
            addr = Address(address)
            if not addr.is_userfriendly():
                raise ValueError("Formato de endereço inválido")
            return addr.to_string()
        except Exception as e:
            logger.error(f"Endereço inválido: {address}")
            raise

    def _parse_balance(self, response: dict) -> float:
        """Extrai o saldo da resposta com tratamento de erros"""
        try:
            stack = response.get('stack', [])
            if not stack:
                logger.debug("Resposta vazia da blockchain")
                return 0.0
                
            balance_entry = stack[0]
            if balance_entry[0] != 'num':
                logger.warning(f"Formato inesperado na stack: {balance_entry}")
                return 0.0
                
            return int(balance_entry[1], 16) / 1e9
        except Exception as e:
            logger.error(f"Falha ao analisar resposta: {str(e)}")
            return 0.0