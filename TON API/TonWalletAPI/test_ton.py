import os
import django
import requests
from django.conf import settings

# Carrega configurações do Django (para acessar variáveis de ambiente, se necessário)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "TonWalletAPI.settings")
django.setup()


# Substitua com o token JWT válido que você gerou pelo /api/v1/auth/login/
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzQ4ODc5NDQzLCJpYXQiOjE3NDg4NzkxNDMsImp0aSI6ImJiYjQwZjVkYTgyZDQyOTQ4YzUxOWNmNmY0ZmFmYzczIiwidXNlcl9pZCI6MTh9.q9ugvz2XLj_L3NNI8F-Wnzc9UlgakqLUn8ifzUrX27c"

def test_wallet_endpoint():
    url = "http://127.0.0.1:8000/api/v1/wallet/"
    headers = {
        'Authorization': f'Bearer {TOKEN}'
    }
    response = requests.get(url, headers=headers)
    print("Status code:", response.status_code)
    
    try:
        json_data = response.json()
        print("Resposta JSON:", json_data)
    except requests.exceptions.JSONDecodeError:
        print("Erro ao decodificar JSON. Conteúdo retornado:", response.text)

    print("Status code:", response.status_code)
    print("Resposta JSON:", response.json())

if __name__ == "__main__":
    test_wallet_endpoint()
