import requests

address = "0QA2AaV8xsOChhYb-Xf0k8Z-Q_WsZgaI35eeJM9tMQCDbE6T"
url = f"https://testnet.toncenter.com/api/v2/getAddressInformation?address={address}"

response = requests.get(url)
data = response.json()
print(data)
if 'result' in data and 'balance' in data['result']:
    balance = int(data['result']['balance']) / 1e9
    print(f"Saldo em TON: {balance}")
else:
    print("Saldo não encontrado ou endereço não ativado.") 