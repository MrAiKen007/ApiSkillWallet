# ApiSkillWallet

Este documento descreve como configurar e testar cada endpoint da API ApiSkillWallet (TonWalletAPI) para gerenciamento de carteiras e transações na TON Blockchain.

1. Descrição

A ApiSkillWallet é uma API RESTful desenvolvida em Django e Django REST Framework que oferece:

Registro e autenticação de usuários (JWT).

Criação e gerenciamento de carteiras TON.

Envio e confirmação de transações (Toncoin).

Recebimento de webhooks para confirmação de transações.

Documentação interativa via Swagger/OpenAPI.

Proteção com rate limiting e throttling.

Containerização com Docker & Docker Compose.

2. Pré-requisitos

Git

Docker >= 20.10

Docker Compose >= 1.29

Python 3.10+ (caso queira executar local sem Docker)

3. Configuração do Projeto

Clone o repositório

git clone https://github.com/MrAiKen007/ApiSkillWallet.git
cd ApiSkillWallet/TON\ API/TonWalletAPI

Crie o arquivo de variáveis de ambiente .env na raiz do projeto:

SECRET_KEY=your_django_secret_key
DEBUG=False
TON_API_KEY=your_ton_api_key
CRYPTO_SALT=your_pbkdf2_salt
CRYPTO_SECRET=your_crypto_secret

POSTGRES_DB=tonwallet
POSTGRES_USER=tonuser
POSTGRES_PASSWORD=tonpassword

Inicie os containers Docker

docker-compose up -d --build

Aplique migrações e crie um superusuário

docker-compose exec web python manage.py migrate
docker-compose exec web python manage.py createsuperuser

Verifique

API disponível em: http://localhost:8000/

Swagger UI em: http://localhost:8000/api/docs/

4. Autenticação

Todas as requisições a endpoints protegidos devem incluir o header:

Authorization: Bearer <ACCESS_TOKEN>

Os tokens são obtidos via endpoint de login.

5. Endpoints e Exemplos de Teste

5.1. Autenticação de Usuário

5.1.1. Registrar Usuário

Método: POST

URL: /api/auth/register/

Payload (JSON):

{
  "username": "usuario1",
  "password": "Pa$$w0rd123"
}

Exemplo cURL:

curl -X POST http://localhost:8000/api/auth/register/ \
     -H "Content-Type: application/json" \
     -d '{"username":"usuario1","password":"Pa$$w0rd123"}'

5.1.2. Login (Obter Tokens JWT)

Método: POST

URL: /api/auth/login/

Payload (JSON):

{
  "username": "usuario1",
  "password": "Pa$$w0rd123"
}

Exemplo cURL:

curl -X POST http://localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"username":"usuario1","password":"Pa$$w0rd123"}'

Resposta (JSON):

{
  "access": "<ACCESS_TOKEN>",
  "refresh": "<REFRESH_TOKEN>"
}

5.2. Endpoints de Carteira

Importante: todos os exemplos a seguir usam: -H "Authorization: Bearer <ACCESS_TOKEN>"

5.2.1. Listar Carteiras

Método: GET

URL: /api/wallets/

Parâmetros Opcionais:

page: número da página (padrão: 1)

page_size: itens por página (padrão: 10)

Exemplo cURL:

curl http://localhost:8000/api/wallets/?page=1&page_size=5 \
     -H "Authorization: Bearer <ACCESS_TOKEN>"

5.2.2. Criar Carteira

Método: POST

URL: /api/wallets/

Payload: não requer JSON

Exemplo cURL:

curl -X POST http://localhost:8000/api/wallets/ \
     -H "Authorization: Bearer <ACCESS_TOKEN>"

5.2.3. Detalhar Carteira

Método: GET

URL: /api/wallets/{id}/

Exemplo cURL:

curl http://localhost:8000/api/wallets/13/ \
     -H "Authorization: Bearer <ACCESS_TOKEN>"

5.3. Endpoints de Transação

5.3.1. Enviar Toncoin

Método: POST

URL: /api/transactions/send/

Payload (JSON):

{
  "from_wallet": 13,
  "to_address": "EQBg...",
  "amount": "0.5",
  "fee": "0.01"
}

Exemplo cURL:

curl -X POST http://localhost:8000/api/transactions/send/ \
     -H "Authorization: Bearer <ACCESS_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"from_wallet":13,"to_address":"EQBg...","amount":"0.5","fee":"0.01"}'

5.3.2. Listar Transações

Método: GET

URL: /api/transactions/?wallet={wallet_id}

Filtros Opcionais:

status: pending ou confirmed

date_from, date_to: intervalo YYYY-MM-DD

Exemplo cURL:

curl http://localhost:8000/api/transactions/?wallet=13&status=pending \
     -H "Authorization: Bearer <ACCESS_TOKEN>"

5.3.3. Detalhar Transação

Método: GET

URL: /api/transactions/{id}/

Exemplo cURL:

curl http://localhost:8000/api/transactions/27/ \
     -H "Authorization: Bearer <ACCESS_TOKEN>"

5.3.4. Webhook de Confirmação

Método: POST

URL: /api/transactions/webhook/

Payload (TON API Callback):

{
  "transaction_id": 27,
  "status": "confirmed",
  "block_id": "0:abcd1234...",
  "timestamp": "2025-04-25T12:06:30Z"
}

Exemplo cURL:

curl -X POST http://localhost:8000/api/transactions/webhook/ \
     -H "Content-Type: application/json" \
     -d '{"transaction_id":27,"status":"confirmed","block_id":"0:abcd1234...","timestamp":"2025-04-25T12:06:30Z"}'

6. Testes Automatizados

Para executar os testes unitários e de integração:

docker-compose exec web python manage.py test

7. Documentação Interativa

Acesse o Swagger UI para explorar e testar todos os endpoints:

http://localhost:8000/api/docs/

8. Contribuição

Faça um fork do repositório.

Crie uma branch: git checkout -b feature/nova-funcionalidade.

Commit suas alterações: git commit -m "Adiciona nova funcionalidade".

Push para a branch: git push origin feature/nova-funcionalidade.

Abra um Pull Request.

Por favor, siga o padrão de estilo (Black, isort) e garanta que todos os testes passem.

Boa diversão testando a API!