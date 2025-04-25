# ApiSkillWallet

**TonWalletAPI**

Uma API RESTful construída com Django e Django REST Framework para gerenciar carteiras e transações na TON Blockchain.

---

## 📝 Descrição

TonWalletAPI fornece endpoints para:
- Registro e autenticação de usuários
- Criação e gerenciamento de carteiras TON
- Envio e confirmação de transações (Toncoin)
- Recebimento de webhooks de confirmação

A arquitetura segue boas práticas de separação de camadas, utilizando Serializers, ViewSets e Services para manter o código modular e testável.

---

## 🚀 Funcionalidades Principais

- **Cadastro e Login** via JSON Web Tokens (JWT)
- **Criação automática** de carteiras com derivação de chaves seguras (PBKDF2)
- **Envio de transações** com status `pending` e confirmação via webhook
- **Endpoints RESTful** gerados com ViewSets e Routers
- **Documentação interativa** Swagger/OpenAPI com drf-spectacular
- **Rate Limiting** e **Throttling** para proteger os endpoints
- **Docker & Docker Compose** para desenvolvimento local

---

## 📦 Pré-requisitos

- Docker & Docker Compose
- Python 3.10+
- Git

---

## ⚙️ Instalação e Setup

1. Clone o repositório:
   ```bash
   git clone https://github.com/MrAiKen007/ApiSkillWallet.git
   cd ApiSkillWallet/TON\ API/TonWalletAPI
   ```

2. Crie um arquivo `.env` na raiz com as variáveis abaixo:
   ```env
   SECRET_KEY=your_django_secret_key
   DEBUG=False
   TON_API_KEY=your_ton_api_key
   CRYPTO_SALT=your_pbkdf2_salt
   CRYPTO_SECRET=your_crypto_secret

   POSTGRES_DB=tonwallet
   POSTGRES_USER=tonuser
   POSTGRES_PASSWORD=tonpassword
   ```

3. Inicialize os containers Docker:
   ```bash
   docker-compose up -d --build
   ```

4. Aplique migrações e crie superusuário:
   ```bash
   docker-compose exec web python manage.py migrate
   docker-compose exec web python manage.py createsuperuser
   ```

5. Acesse a API em `http://localhost:8000/` e a documentação Swagger em `http://localhost:8000/api/docs/`

---

## 🔧 Configuração de Ambiente

Ajuste as seguintes configurações em `settings.py` conforme necessário:

- **CORS_ALLOWED_ORIGINS**: defina as origens permitidas na produção
- **ALLOWED_HOSTS**: inclua seu domínio/host
- **DEBUG**: NEVER use `True` em produção

---

## 📖 Uso Básico

### Autenticação 📡

Todas as requisições autenticadas devem incluir o header:

```
Authorization: Bearer <seu_token_jwt>
```

### Endpoints de Usuário 👤

- **Registrar usuário**  
  `POST /api/auth/register/`  
  Payload:
  ```json
  {
    "username": "user1",
    "password": "Pa$$w0rd"
  }
  ```
  Resposta:
  ```json
  {
    "id": 1,
    "username": "user1"
  }
  ```

- **Login (Obter JWT)**  
  `POST /api/auth/login/`  
  Payload:
  ```json
  {
    "username": "user1",
    "password": "Pa$$w0rd"
  }
  ```
  Resposta:
  ```json
  {
    "access": "eyJ0eXAi...",
    "refresh": "eyJ0eXAi..."
  }
  ```

### Endpoints de Carteira 🏦

- **Listar carteiras**  
  `GET /api/wallets/`  
  Query params opcionais:
  - `page`: número da página (padrão: 1)  
  - `page_size`: itens por página (padrão: 10)  

  Exemplo:
  ```bash
  curl -H "Authorization: Bearer <token>" http://localhost:8000/api/wallets/?page=2&page_size=5
  ```
  Resposta:
  ```json
  {
    "count": 12,
    "next": "...",
    "previous": "...",
    "results": [
      {
        "id": 5,
        "address": "EQBg...",
        "balance": "12.3456"
      }
    ]
  }
  ```

- **Criar carteira**  
  `POST /api/wallets/`  
  Sem payload. Retorna:
  ```json
  {
    "id": 13,
    "address": "EQCd...",
    "balance": "0.0000"
  }
  ```

- **Detalhar carteira**  
  `GET /api/wallets/<id>/`  
  Resposta:
  ```json
  {
    "id": 13,
    "address": "EQCd...",
    "balance": "0.0000",
    "created_at": "2025-04-25T12:00:00Z"
  }
  ```

### Endpoints de Transações 💸

- **Enviar Toncoin**  
  `POST /api/transactions/send/`  
  Payload:
  ```json
  {
    "from_wallet": 13,
    "to_address": "EQBg...",
    "amount": "0.5",
    "fee": "0.01"
  }
  ```
  Resposta inicial:
  ```json
  {
    "id": 27,
    "status": "pending",
    "to_address": "EQBg...",
    "amount": "0.5",
    "fee": "0.01",
    "created_at": "2025-04-25T12:05:00Z"
  }
  ```

- **Listar transações**  
  `GET /api/transactions/?wallet=<id>`  
  Filtros opcionais:
  - `status`: `pending` ou `confirmed`  
  - `date_from`, `date_to`: filtro por intervalo de datas (YYYY-MM-DD)

- **Detalhar transação**  
  `GET /api/transactions/<id>/`  

- **Webhook de Confirmação**  
  `POST /api/transactions/webhook/`  
  Payload enviado pela TON API:
  ```json
  {
    "transaction_id": 27,
    "status": "confirmed",
    "block_id": "0:abcd1234...",
    "timestamp": "2025-04-25T12:06:30Z"
  }
  ```
  Ao receber, a API atualiza `Transaction.status` e ajusta o saldo das carteiras.

### Tratamento de Erros ⚠️

- API retorna códigos HTTP padrões (400, 401, 404, 500)  
- Exemplo de erro 400:
  ```json
  {
    "detail": "Amount must be positive"
  }
  ```

---

## 🛠️ Estrutura de Pastas

```
TonWalletAPI/
├── api/
│   ├── serializers/       # Serializers para validação de dados
│   ├── services/          # Lógica de negócio (use cases)
│   ├── viewsets.py        # ViewSets definidos para cada recurso
│   ├── urls.py            # Roteamento com DefaultRouter
│   └── tests/             # Testes unitários e de integração
├── core/
│   ├── crypto.py          # Derivação de chaves e criptografia
│   └── settings.py        # Configurações do Django
├── docker-compose.yml
├── Dockerfile
└── manage.py
```

---

## 📚 Documentação API

Acesse Swagger UI em: `http://<host>/api/docs/` para visualizar e testar todos os endpoints.

---

## 🤝 Contribuição

1. Faça um fork do projeto
2. Crie uma branch: `git checkout -b feature/nova-funcionalidade`
3. Commit suas alterações: `git commit -m 'Adiciona nova funcionalidade'`
4. Push para a branch: `git push origin feature/nova-funcionalidade`
5. Abra um Pull Request

Por favor, siga as diretrizes de estilo (Black, isort) e garanta que todos os testes passem.

---