from django.db.models import Q
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import User, Wallet, Transaction
from .utils import (
    generate_seed_phrase,
    validate_seed_phrase,
    encrypt_seed,
    decrypt_seed,
    sign_transaction,
    broadcast_transaction,
    BlockchainError,
    get_public_key, 
    derive_ton_address_onchain
)
from .serializers import WalletSerializer, TransactionSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from decimal import Decimal
import time
import logging

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.permissions import AllowAny
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction

logger = logging.getLogger(__name__)

@api_view(['GET'])
def api_root(request, format=None):
    return Response({
        'register': reverse('register', request=request, format=format),
        'login': reverse('login', request=request, format=format),
        'wallet': reverse('wallet', request=request, format=format),
        'documentation': reverse('schema-swagger-ui', request=request)
    })

def create_jwt_token(user):
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token)

class RegisterView(APIView):
    authentication_classes = []       # Desabilita autenticação JWT
    permission_classes = [AllowAny]   # Permite acesso público

    def post(self, request):
        """Registro de nova carteira TON com seed phrase gerada automaticamente"""
        try:
            data = request.data
            required_fields = {'email', 'password'}
            
            # Validação de campos obrigatórios
            if missing := required_fields - set(data.keys()):
                return Response(
                    {"error": f"Campos obrigatórios faltando: {', '.join(missing)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            email = data['email'].lower().strip()
            password = data['password']

            # Validação de email único
            if User.objects.filter(email=email).exists():
                return Response(
                    {"error": "Email já registrado no sistema"},
                    status=status.HTTP_409_CONFLICT
                )

            # Validação de força da senha
            try:
                validate_password(password)
            except ValidationError as e:
                return Response(
                    {"error": ", ".join(e.messages)},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 1. Geração da seed phrase
            seed = generate_seed_phrase()
            # 2. Derivar a public key (hex 64 chars)
            public_key = get_public_key(seed)
            # 3. Derivar o address diretamente da blockchain
            address = derive_ton_address_onchain(public_key)

            # Criação do usuário e da wallet em transação atômica
            with transaction.atomic():
                user = User.objects.create_user(
                    email=email,
                    password=password,
                    seed_phrase=encrypt_seed(seed),
                    public_key=public_key
                )
                Wallet.objects.create(
                    user=user,
                    token_type='TON',
                    contract_address=address
                )

            # Resposta de sucesso
            return Response({
                "public_key": public_key,
                "contract_address": address,
                "seed_phrase": seed,
                "warning": "ESTA É A ÚNICA VEZ QUE A SEED PHRASE SERÁ EXIBIDA! GUARDE COM SEGURANÇA!"
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            import traceback, logging
            logging.getLogger(__name__).exception("Erro em RegisterView")
            return Response(
                {
                    "error": str(e),
                    "trace": traceback.format_exc()
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ImportWalletView(APIView):
    """
    Endpoint para importação de carteira existente
    Métodos permitidos: POST (importação), GET (documentação)
    """
    
    authentication_classes = []  # Desabilita autenticação JWT
    permission_classes = [AllowAny]  # Permite acesso público

    def post(self, request):
        """Importa uma carteira usando seed phrase existente"""
        try:
            data = request.data
            required_fields = {'email', 'password', 'seed_phrase'}
            
            # Validação de campos obrigatórios
            if missing := required_fields - set(data.keys()):
                return Response(
                    {"error": f"Campos obrigatórios faltando: {', '.join(missing)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validação da seed phrase
            if not validate_seed_phrase(data['seed_phrase']):
                return Response(
                    {"error": "Seed phrase inválida. Deve conter 24 palavras no formato BIP-39"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Geração da chave pública
            public_key = get_public_key(data['seed_phrase'])
            
            # Verifica se a carteira já existe
            if User.objects.filter(public_key=public_key).exists():
                return Response(
                    {"error": "Carteira já registrada no sistema"},
                    status=status.HTTP_409_CONFLICT
                )

            # Criação do usuário
            user = User.objects.create_user(
                email=data['email'],
                password=data['password'],
                seed_phrase=encrypt_seed(data['seed_phrase']),
                public_key=public_key
            )

            # Resposta de sucesso
            return Response({
                "public_key": public_key,
                "message": "Carteira importada com sucesso",
                "warning": "Guarde suas credenciais com segurança!"
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Log de erro detalhado (implementar logger)
            return Response(
                {"error": "Erro interno no servidor"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request):
        """Documentação do endpoint de importação"""
        return Response({
            "description": "Importação de carteira TON existente",
            "instruções": {
                "1": "Forneça email, senha e seed phrase válida",
                "2": "A seed phrase deve ter 24 palavras no formato BIP-39",
                "3": "A chave pública será gerada automaticamente"
            },
            "exemplo_requisicao": {
                "email": "user@example.com",
                "password": "SenhaF0rte!",
                "seed_phrase": "palavra1 palavra2 ... palavra24"
            },
            "resposta_sucesso": {
                "public_key": "3FZbgi29...",
                "message": "Carteira importada com sucesso"
            }
        })

class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        seed_phrase = request.data.get('seed_phrase')

        if not email or not seed_phrase:
            return Response(
                {"error": "Email e seed phrase são obrigatórios"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(email=email)
            decrypted_seed = decrypt_seed(user.seed_phrase)
            
            if seed_phrase != decrypted_seed:
                return Response(
                    {'error': 'Seed phrase inválida'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            token = create_jwt_token(user)
            return Response({
                'token': token,
                'public_key': user.public_key,
                'email': user.email
            })
            
        except User.DoesNotExist:
            return Response(
                {'error': 'Usuário não encontrado'},
                status=status.HTTP_404_NOT_FOUND
            )

class WalletView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        wallets = request.user.wallets.all()
        transactions = Transaction.objects.filter(
            Q(sender=request.user) | 
            Q(receiver=request.user)
        ).order_by('-timestamp')[:50]
        
        return Response({
            'public_key': request.user.public_key,
            'wallets': WalletSerializer(wallets, many=True).data,
            'transactions': TransactionSerializer(transactions, many=True).data
        })

class SendTransactionView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        receiver = request.data.get('receiver')
        amount = Decimal(request.data.get('amount'))
        token = request.data.get('token', 'TON')
        
        try:
            wallet = request.user.wallets.get(token_type=token)
            if wallet.balance < amount:
                return Response({'error': 'Saldo insuficiente'}, status=status.HTTP_400_BAD_REQUEST)
                
            tx_data = {
                'from': request.user.public_key,
                'to': receiver,
                'amount': str(amount),
                'timestamp': int(time.time())
            }
            
            signature = sign_transaction(
                decrypt_seed(request.user.seed_phrase),
                tx_data
            )
            
            result = broadcast_transaction(tx_data, signature)
            Transaction.objects.create(
                sender=request.user,
                receiver=User.objects.get(public_key=receiver),
                amount=amount,
                token=token,
                tx_hash=result['hash'],
                status='pending'
            )
            
            return Response({'tx_hash': result['hash']})
            
        except BlockchainError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'error': 'Destinatário não encontrado'}, status=status.HTTP_404_NOT_FOUND)
        
class TonWebhook(APIView):
    """Processador de eventos da blockchain TON"""
    
    def post(self, request):
        try:
            event = request.data.get('event')
            logger.info(f"Evento recebido: {event['type']}")
            
            if event['type'] == 'transaction':
                self.handle_transaction(event['data'])
            
            return Response({"status": "processed"}, status=200)
        except Exception as e:
            logger.error(f"Erro no webhook: {str(e)}")
            return Response({"error": "Processamento falhou"}, status=400)

    def handle_transaction(self, data):
        try:
            # Sua lógica de processamento de transação aqui
            return Response({"status": "success"})
        except Exception as e:
            logger.error(f"Erro ao processar transação: {str(e)}")
            raise