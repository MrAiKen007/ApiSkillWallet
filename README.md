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
* Python 3.10+ (somente se for executar local sem Docker)

---

## 3. Configuração do Projeto

1. **Clone o repositório**

   ```bash
   git clone https://github.com/MrAiKen007/ApiSkillWallet.git
   cd ApiSkillWallet/TON\ API/TonWalletAPI
   ```

2. **Copie o template `.env.sample` para `.env`** e defina as variáveis:

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

4. **Aplique migrações e crie um superusuário**

   ```bash
   docker-compose exec web python manage.py migrate
   docker-compose exec web python manage.py createsuperuser
   ```

5. **Verifique**

   * API disponível em: `http://localhost:8000/`
   * Swagger UI (OpenAPI) em: `http://localhost:8000/schema-swagger-ui/`

---

## 4. Autenticação

* Endpoints públicos não requerem header de autorização.

* Para acessar endpoints protegidos, adicione no header:

  ```http
  Authorization: Bearer <ACCESS_TOKEN>
  ```

* O token *access* é gerado no **login** e dura conforme configuração do `SIMPLE_JWT`.

---

## 5. Endpoints e Exemplos de Teste

> **Nota:** todos os exemplos usam `http://localhost:8000` como base.

### 5.1. Raiz da API

* **Método:** `GET`
* **URL:** `/`
* **Descrição:** retorna as URLs principais.

```bash
curl -X GET http://localhost:8000/ \
     -H "Accept: application/json"
```

### 5.2. Registro de Usuário

* **Método:** `POST`

* **URL:** `/register/`

* **Payload (JSON):**

  ```json
  {
    "email": "usuario@exemplo.com",
    "password": "SenhaForte!123"
  }
  ```

* **Resposta:**

  * `address`: endereço gerado da carteira TON.
  * `seed_phrase`: *seed phrase* para backup.
  * `warning`: lembrete para guardar a frase.

```bash
curl -X POST http://localhost:8000/register/ \
     -H "Content-Type: application/json" \
     -d '{"email":"usuario@exemplo.com","password":"SenhaForte!123"}'
```

---

### 5.3. Importação de Carteira Existente

* **Método:** `POST`

* **URL:** `/import-wallet/`

* **Payload (JSON):**

  ```json
  {
    "email": "novo@exemplo.com",
    "password": "OutraSenha!456",
    "seed_phrase": "palavra1 palavra2 ... palavra12"
  }
  ```

* **Resposta:** dados da carteira importada.

```bash
curl -X POST http://localhost:8000/import-wallet/ \
     -H "Content-Type: application/json" \
     -d '{"email":"novo@exemplo.com","password":"OutraSenha!456","seed_phrase":"palavra1 palavra2 ... palavra12"}'
```

---

### 5.4. Login (JWT)

* **Método:** `POST`

* **URL:** `/login/`

* **Payload (JSON):**

  ```json
  {
    "email": "usuario@exemplo.com",
    "password": "SenhaForte!123"
  }
  ```

* **Resposta:**

  * `token`: token de acesso JWT.
  * `public_key`: chave pública do usuário.
  * `email`: e-mail autenticado.

```bash
curl -X POST http://localhost:8000/login/ \
     -H "Content-Type: application/json" \
     -d '{"email":"usuario@exemplo.com","password":"SenhaForte!123"}'
```

---

### 5.5. Consulta de Carteira

* **Método:** `GET`

* **URL:** `/wallet/`

* **Headers:**

  ```http
  Authorization: Bearer <ACCESS_TOKEN>
  ```

* **Resposta:**

  * `public_key`
  * `wallets`: lista com saldo e endereço.
  * `transactions`: últimas 50 transações (sender/receiver).

```bash
curl -X GET http://localhost:8000/wallet/ \
     -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/json"
```

---

### 5.6. Enviar Transação

* **Método:** `POST`

* **URL:** `/send-transaction/`

* **Headers:**

  ```http
  Authorization: Bearer <ACCESS_TOKEN>
  ```

* **Payload (JSON):**

  ```json
  {
    "receiver": "ed25519:ENDERECO_DESTINO",
    "amount": "1.2345",
    "token": "TON"
  }
  ```

* **Resposta:**

  * `tx_hash`: hash da transação enviada.

```bash
curl -X POST http://localhost:8000/send-transaction/ \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"receiver":"ed25519:ENDERECO_DESTINO","amount":"1.2345","token":"TON"}'
```

---

### 5.7. Webhook de Transações

* **Método:** `POST`

* **URL:** `/webhook/`

* **Payload (exemplo de callback da TON API):**

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

* **Uso:** atualiza o status de `pending` para `confirmed`.

```bash
curl -X POST http://localhost:8000/webhook/ \
     -H "Content-Type: application/json" \
     -d '{"event":{"type":"transaction","data":{"hash":"abcdef123456...","status":"confirmed"}}}'
```

---

## 6. Automação com Scripts

Você pode criar scripts em Bash ou usar **httpie** para chamadas legíveis. Exemplo de script (*script.sh*):

```bash
#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:8000"
EMAIL="teste@ex.com"
PASS="Senha!123"

# 1. Registro
SEED=$(curl -s -X POST $API/register/ -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | jq -r '.seed_phrase')
echo "Seed gerada: $SEED"

# 2. Login
token=$(curl -s -X POST $API/login/ -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | jq -r '.token')
echo "Token: $token"

# 3. Consulta
echo "Carteira:"; curl -s -H "Authorization: Bearer $token" $API/wallet/ | jq

# 4. Enviar 0.1 TON
address=$(curl -s -H "Authorization: Bearer $token" $API/wallet/ | jq -r '.wallets[0].contract_address')
curl -s -X POST $API/send-transaction/ -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "{\"receiver\":\"$address\",\"amount\":\"0.1\",\"token\":\"TON\"}" | jq
```

---

## 7. Testes

* **Unitários & Integração**:

  ```bash
  docker-compose exec web python manage.py test
  ```

---

## 8. Contribution

1. Fork do repositório
2. Branch: `git checkout -b feature/nova-funcionalidade`
3. Code e testes
4. `git push origin feature/nova-funcionalidade`
5. Abra um Pull Request

> Mantenha estilo com **Black** e **isort**. Garanta testes verdes.

---

**Pronto para iniciar!** Qualquer dúvida, entre em contato.
