import os
import django
import requests

# Carrega configurações do Django (para acessar variáveis de ambiente, se necessário)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "TonWalletAPI.settings")
django.setup()

# Substitua com o token JWT válido que você gerou pelo /api/v1/auth/login/
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzQ4ODU3Njc5LCJpYXQiOjE3NDg4NTczNzksImp0aSI6IjY4ZDBiZjg2MTEzMDQ5Yjc4Mzk2MWY0NDY2ODdhYzM3IiwidXNlcl9pZCI6MTh9.fFy-grrvhWzQhCGhFw6Mx2SjBDKAixWX9jHzPKxPb3c"

def test_wallet_endpoint():
    url = "http://localhost:8000/api/v1/wallet/"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
    }
    response = requests.get(url, headers=headers)

    print("Status code:", response.status_code)
    print("Resposta JSON:", response.json())

if __name__ == "__main__":
    test_wallet_endpoint()
