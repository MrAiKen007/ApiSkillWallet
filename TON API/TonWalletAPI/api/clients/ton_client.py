import requests
from pathlib import Path
from pytonlib import TonlibClient
import asyncio
from tonsdk.utils import Address
from tonsdk.contract.wallet import Wallets, WalletVersionEnum
from tonsdk.boc import Cell
from django.conf import settings
import logging
import os

logger = logging.getLogger(__name__)

class PyTONClient:
    def __init__(self):
        self._ensure_network_config()
        self._setup_keystore()
        self._client = None
        
    def _ensure_network_config(self):
        """Garante o uso da configuração da rede (testnet ou mainnet)"""
        network = os.getenv('TON_NETWORK', 'testnet')
        if network == 'mainnet':
            self.ton_config = requests.get(
                'https://ton-blockchain.github.io/global.config.json'
            ).json()
            logger.debug("Configuração da mainnet carregada")
        else:
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
        if self._client is None:
            self._client = TonlibClient(
                ls_index=0,
                config=self.ton_config,
                keystore=self.keystore
            )
            await self._client.init()
            logger.debug("Cliente Tonlib inicializado")
        return self._client

    async def get_wallet_type(self, address: str) -> str:
        """Consulta o tipo de contrato (wallet) do endereço"""
        async def _wrapper():
            client = None
            try:
                validated_addr = self._validate_address(address)
                logger.info(f"Consultando tipo de wallet para endereço: {validated_addr}")
                async with self._get_client() as client:
                    result = await client.get_account_state(validated_addr)
                    if result and result.get('code_hash'):
                        code_hash = result['code_hash']
                        if code_hash == '207dc560c5956de1a49c3464d8e0d3ebc3a3d026a1d422338dc42d0d6f3c1f0e':
                            return 'v3R2'
                        elif code_hash == 'c1a0b7b1b7c1a0b7b1b7c1a0b7b1b7c1a0b7b1b7c1a0b7b1b7c1a0b7b1b7c1a0':
                            return 'v3R5'
                        else:
                            return 'unknown'
                    return 'empty'
            except Exception as e:
                logger.error(f"Falha ao consultar tipo de wallet: {str(e)}")
                return 'error'
        return asyncio.run(_wrapper())

    def get_account_balance(self, address: str) -> float:
        """Obtém o saldo mantendo o formato 0Q... com verificação completa"""
        async def _wrapper():
            client = None
            try:
                validated_addr = self._validate_address(address)
                logger.info(f"Consultando saldo para endereço: {validated_addr}")
                wallet_type = await self.get_wallet_type(validated_addr)
                logger.info(f"Tipo de wallet: {wallet_type}")
                if wallet_type == 'empty':
                    logger.warning(f"Endereço não ativado: {address}")
                    return 0.0
                async with self._get_client() as client:
                    result = await client.get_balance(validated_addr)
                    logger.info(f"Resultado bruto da consulta: {result}")
                    if result is None:
                        logger.warning(f"Saldo não encontrado para o endereço: {address}")
                        return 0.0
                    balance = result / 1e9
                    logger.info(f"Saldo convertido: {balance} TON")
                    return balance
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

    async def get_seqno(self, address: str) -> int:
        """Obtém o seqno atual da carteira."""
        try:
            client = await self._get_client()
            result = await client.raw_get_account_state(address)
            seqno = result.get('account_state', {}).get('wallet', {}).get('seqno', 0)
            return seqno
        except Exception as e:
            logger.exception(f"Erro ao obter seqno: {str(e)}")
            return 0

    async def _sign_message_async(self, from_address: str, to_address: str, amount: int, private_key: str) -> str:
        """Versão assíncrona do método sign_message."""
        try:
            # Valida endereços
            from_addr = Address(from_address)
            to_addr_obj = Address(to_address) # Renomeado para evitar conflito

            # Obtém o seqno atual
            seqno = await self.get_seqno(from_address)
            logger.info(f"Seqno atual da carteira: {seqno}")

            # Converte a chave privada de hex para bytes
            private_key_bytes = bytes.fromhex(private_key)

            # Cria a wallet v3R2
            from tonsdk.contract.wallet import WalletV3ContractR2
            from tonsdk.boc import Cell # Manter importação de Cell

            wallet = WalletV3ContractR2(
                public_key=private_key_bytes,  # A chave pública será derivada da privada
                private_key=private_key_bytes,
                workchain=0
            )

            # Cria a mensagem de transferência usando create_transfer_message
            # Este método retorna um dicionário, não um objeto com to_boc() diretamente
            transfer_result_dict = wallet.create_transfer_message(
                to_addr=to_addr_obj,  # Usando 'to_addr' conforme encontrado
                amount=amount,
                seqno=seqno,
                # Outros argumentos opcionais podem ser adicionados se necessário (payload, send_mode, etc.)
            )

            # Acessa o objeto Cell da mensagem externa a partir do dicionário retornado
            signed_message_cell = transfer_result_dict.get("message")

            if not signed_message_cell or not isinstance(signed_message_cell, Cell):
                 raise ValueError("Não foi possível obter o objeto Cell da mensagem assinada.")

            # Converte o objeto Cell para BOC
            boc = signed_message_cell.to_boc(False)
            return boc.hex()

        except Exception as e:
            logger.exception(f"Erro ao assinar mensagem: {str(e)}")
            raise

    def sign_message(self, from_address: str, to_address: str, amount: int, private_key: str) -> str:
        """Assina uma mensagem de transferência TON."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self._sign_message_async(from_address, to_address, amount, private_key)
        )

    async def _broadcast_transaction_async(self, signed_boc: str) -> str:
        """Versão assíncrona do método broadcast_transaction."""
        try:
            client = await self._get_client()
            result = await client.send_boc(signed_boc)
            if result and 'transaction_id' in result:
                return result['transaction_id']
            raise Exception("Resposta inválida do servidor")
        except Exception as e:
            logger.exception(f"Erro ao broadcast da transação: {str(e)}")
            raise

    def broadcast_transaction(self, signed_boc: str) -> str:
        """Envia o BOC assinado para a rede."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self._broadcast_transaction_async(signed_boc)
        )