import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("DJANGO_API_URL", "http://127.0.0.1:8000")
EMAIL = os.getenv("TEST_EMAIL", "usuario@exemplo.com")
PASSWORD = os.getenv("TEST_PASSWORD", "SenhaForte!123")
SEED = os.getenv("TEST_SEED", "palavra1 palavra2 ... palavra24")
RECEIVER = os.getenv("RECEIVER", "ENDERECO_DESTINO")


def register():
    url = f"{API_URL}/api/v1/auth/register/"
    data = {"email": EMAIL, "password": PASSWORD}
    r = requests.post(url, json=data)
    print("[REGISTER]", r.status_code, r.text)
    return r

def login():
    url = f"{API_URL}/api/v1/auth/login/"
    data = {"email": EMAIL, "password": PASSWORD}
    r = requests.post(url, json=data)
    print("[LOGIN]", r.status_code, r.text)
    if r.status_code == 200:
        return r.json().get("token")
    return None

def wallet(token):
    url = f"{API_URL}/api/v1/wallet/"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers)
    print("[WALLET]", r.status_code, r.text)
    return r

def import_wallet(token):
    url = f"{API_URL}/api/v1/auth/import/"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"email": EMAIL, "password": PASSWORD, "seed_phrase": SEED}
    r = requests.post(url, json=data, headers=headers)
    print("[IMPORT WALLET]", r.status_code, r.text)
    return r

def send_transaction(token):
    url = f"{API_URL}/api/v1/wallet/send/"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"receiver": RECEIVER, "amount": "0.1"}
    r = requests.post(url, json=data, headers=headers)
    print("[SEND TRANSACTION]", r.status_code, r.text)
    return r

if __name__ == "__main__":
    register()
    token = login()
    if token:
        wallet(token)
        import_wallet(token)
        send_transaction(token)
    else:
        print("Falha ao obter token JWT.") 