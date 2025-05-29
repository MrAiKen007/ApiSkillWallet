# ApiSkillWallet (TonWalletAPI)

Este documento descreve como configurar, executar e testar cada endpoint da API **ApiSkillWallet** — uma API RESTful em **Django** e **Django REST Framework** para gerenciamento de carteiras e transações na blockchain TON.

---

## 1. Visão Geral

A **ApiSkillWallet** oferece as seguintes funcionalidades:

* **Registro** de usuário com geração de *seed phrase* e carteira TON.
* **Importação** de carteira existente via *seed phrase*.
* **Autenticação** de usuários através de JWT.
* **Consulta** de saldo e histórico de transações.
* **Envio** de transações TON.
* **Recebimento** de webhooks para confirmação de transações.
* **Documentação** interativa via Swagger/OpenAPI.

---

## 2. Pré-requisitos

* Git
* Docker Engine >= 20.10
* Docker Compose >= 1.29
* Python 3.10+ (para execução local sem Docker)

---

## 3. Configuração do Projeto

1. **Clone o repositório**

   ```bash
   git clone https://github.com/MrAiKen007/ApiSkillWallet.git
   cd ApiSkillWallet/TON\ API/TonWalletAPI
   ```

2. **Copie `.env.sample` para `.env`** e defina as variáveis:

   ```ini
   SECRET_KEY=your_django_secret_key
   DEBUG=False
   TON_API_KEY=your_ton_api_key
   CRYPTO_SALT=your_pbkdf2_salt
   CRYPTO_SECRET=your_crypto_secret

   POSTGRES_DB=tonwallet
   POSTGRES_USER=tonuser
   POSTGRES_PASSWORD=tonpassword
   ```

3. **Inicie os containers**

   ```bash
   docker-compose up -d --build
   ```

4. **Migre e crie superuser**

   ```bash
   docker-compose exec web python manage.py migrate
   docker-compose exec web python manage.py createsuperuser
   ```

5. **Acesse**

   * API em: `http://localhost:8000/`
   * Swagger UI em: `http://localhost:8000/schema-swagger-ui/`

---

## 4. Autenticação

* Endpoints públicos não requerem header de autorização.
* Para endpoints protegidos, inclua no header:

  ```http
  Authorization: Bearer <ACCESS_TOKEN>
  ```
* O token *access* é gerado no **login**.

---

## 5. Endpoints e Exemplos

> Base: `http://localhost:8000`

### 5.1 Raiz da API

* **GET /**
* Descrição: lista URLs principais.

```bash
curl -X GET http://localhost:8000/ \
     -H "Accept: application/json"
```

### 5.2 Registro de Usuário

* **POST /auth/register/**

**Payload:**

```json
{
  "email": "usuario@exemplo.com",
  "password": "SenhaForte!123"
}
```

**Resposta:**

* `address`
* `seed_phrase`
* `warning`

```bash
curl -X POST http://localhost:8000/auth/register/ \
     -H "Content-Type: application/json" \
     -d '{"email":"usuario@exemplo.com","password":"SenhaForte!123"}'
```

### 5.3 Importação de Carteira

* **POST /auth/import/**

**Payload:**

```json
{
  "email": "novo@exemplo.com",
  "password": "OutraSenha!456",
  "seed_phrase": "palavra1 palavra2 ... palavra12"
}
```

```bash
curl -X POST http://localhost:8000/auth/import/ \
     -H "Content-Type: application/json" \
     -d '{"email":"novo@exemplo.com","password":"OutraSenha!456","seed_phrase":"palavra1 palavra2 ... palavra12"}'
```

### 5.4 Login (JWT)

* **POST /auth/login/**

**Payload:**

```json
{
  "email": "usuario@exemplo.com",
  "password": "SenhaForte!123"
}
```

**Resposta:**

* `token`
* `public_key`
* `email`

```bash
curl -X POST http://localhost:8000/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"email":"usuario@exemplo.com","password":"SenhaForte!123"}'
```

### 5.5 Consulta de Carteira

* **GET /wallet/**

**Headers:**

```http
Authorization: Bearer <ACCESS_TOKEN>
```

**Resposta:**

* `public_key`
* `wallets`
* `transactions`

```bash
curl -X GET http://localhost:8000/wallet/ \
     -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/json"
```

### 5.6 Enviar Transação

* **POST /wallet/send/**

**Headers:**

```http
Authorization: Bearer <ACCESS_TOKEN>
```

**Payload:**

```json
{
  "receiver": "ed25519:ENDERECO_DESTINO",
  "amount": "1.2345",
  "token": "TON"
}
```

```bash
curl -X POST http://localhost:8000/wallet/send/ \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"receiver":"ed25519:ENDERECO_DESTINO","amount":"1.2345","token":"TON"}'
```

### 5.7 Webhook

* **POST /ton/webhook/**

**Payload:**

```json
{
  "event": {
    "type": "transaction",
    "data": {
      "hash": "abcdef123456...",
      "status": "confirmed"
    }
  }
}
```

```bash
curl -X POST http://localhost:8000/ton/webhook/ \
     -H "Content-Type: application/json" \
     -d '{"event":{"type":"transaction","data":{"hash":"abcdef123456...","status":"confirmed"}}}'
```

---

## 6. Script de Automação

```bash
#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:8000"
EMAIL="teste@ex.com"
PASS="Senha!123"

# 1. Registro
SEED=$(curl -s -X POST $API/auth/register/ -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | jq -r '.seed_phrase')
echo "Seed: $SEED"

# 2. Login
token=$(curl -s -X POST $API/auth/login/ -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | jq -r '.token')
echo "Token: $token"

# 3. Consulta
curl -s -H "Authorization: Bearer $token" $API/wallet/ | jq

# 4. Enviar 0.1 TON
address=$(curl -s -H "Authorization: Bearer $token" $API/wallet/ | jq -r '.wallets[0].contract_address')
curl -s -X POST $API/wallet/send/ -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "{\"receiver\":\"$address\",\"amount\":\"0.1\",\"token\":\"TON\"}" | jq
```

---

## 7. Testes

```bash
docker-compose exec web python manage.py test
```

---

## 8. Contribuição

1. Fork do repositório
2. `git checkout -b feature/nova-funcionalidade`
3. Desenvolvimento e testes
4. `git push origin feature/nova-funcionalidade`
5. Abra Pull Request

> Siga padrões de estilo (**Black**, **isort**) e garanta testes verdes.