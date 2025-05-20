# test_ton.py
import os
import django

# Configura o Django para permitir uso de settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "TonWalletAPI.settings")
django.setup()

from api.clients.ton_client import PyTONClient


def main():
    client = PyTONClient()
    info = client.get_masterchain_info()
    print("Masterchain Info:", info)


if __name__ == "__main__":
    main()
