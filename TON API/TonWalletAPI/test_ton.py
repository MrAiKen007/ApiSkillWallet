import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "TonWalletAPI.settings")
django.setup()

from api.clients.ton_client import PyTONClient

client = PyTONClient()
# Substitua pelo endereço que foi gerado no registro
address = "0QC5WkbP4lSHfWph8LxEeJw9NOQLpAtdrDH2F7ZNf7NeqwxD"  

try:
    balance = client.get_account_balance(address)
    print("Saldo:", balance, "TON")
except Exception as e:
    print("Erro ao consultar saldo:", e)