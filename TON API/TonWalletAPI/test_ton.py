import os
import django
import logging
from tonsdk.utils import Address

# Configuração básica de logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "TonWalletAPI.settings")
django.setup()

from api.clients.ton_client import PyTONClient

def test_ton_client():
    client = PyTONClient()
    address = "0QC5WkbP4lSHfWph8LxEeJw9NOQLpAtdrDH2F7ZNf7NeqwxD"
    
    print("\n=== Iniciando Teste do Cliente TON ===")
    
    try:
        # Validação do endereço
        print("\n[1/3] Validando endereço...")
        addr_obj = Address(address)
        if not addr_obj.is_user_friendly:
            raise ValueError("Formato de endereço inválido")
        print(f"✓ Endereço válido: {address}")
        print(f"• Formato raw: {addr_obj.to_string(is_user_friendly=False)}")
        print(f"• Rede: {'testnet' if addr_obj.is_test_only() else 'mainnet'}")  # Correto

        # Consulta de saldo
        print("\n[2/3] Consultando blockchain...")
        balance = client.get_account_balance(address)
        
        # Verificação final
        print("\n[3/3] Resultados:")
        print(f"✓ Saldo recuperado: {balance} TON")
        print(f"• Endereço verificado: {address}")
        
        if balance == 0:
            print("\n⚠️  Aviso: Saldo zero detectado. Verifique:")
            print("- A conta realmente possui saldo na testnet?")
            print("- O contrato foi devidamente implantado?")
            print("- A transação inicial foi realizada?")

    except Exception as e:
        print("\n❌ Falha no teste:")
        print(f"Erro: {str(e)}")
        print("Solução: Verifique:")
        print("- Formato do endereço (deve ser 0Q... para testnet)")
        print("- Conexão com a internet")
        print("- Configuração do pytonlib")
    finally:
        print("\n=== Teste Concluído ===")

if __name__ == "__main__":
    test_ton_client()