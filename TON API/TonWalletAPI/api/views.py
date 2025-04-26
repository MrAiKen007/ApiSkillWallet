from django.db.models import Q
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction

from .models import User, Wallet, Transaction
from .serializers import WalletSerializer, TransactionSerializer
from .utils import (
    create_wallet,
    encrypt_seed,
    decrypt_seed,
    sign_transaction,
    broadcast_transaction,
    validate_seed_phrase,
    derive_keys_and_address,
    BlockchainError
)

import time
import logging
from decimal import Decimal

logger = logging.getLogger(__name__)

@api_view(['GET'])
def api_root(request, format=None):
    return Response({
        'register': reverse('register', request=request, format=format),
        'import_wallet': reverse('import-wallet', request=request, format=format),
        'login': reverse('login', request=request, format=format),
        'wallet': reverse('wallet', request=request, format=format),
        'documentation': reverse('schema-swagger-ui', request=request)
    })


def create_jwt_token(user):
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token)


class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        required_fields = {'email', 'password'}
        if missing := required_fields - set(data.keys()):
            return Response(
                {"error": f"Campos obrigatórios faltando: {', '.join(missing)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        email = data['email'].lower().strip()
        password = data['password']

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email já registrado"}, status=status.HTTP_409_CONFLICT)

        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": ", ".join(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

        # Gera carteira TON usando utilitário create_wallet
        try:
            address, private_key = create_wallet()
        except Exception as e:
            logger.exception("Erro ao criar carteira TON")
            return Response({"error": "Falha ao gerar carteira"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Encripta a chave privada para armazenamento
        encrypted_seed = encrypt_seed(private_key)

        with transaction.atomic():
            user = User.objects.create_user(
                email=email,
                password=password,
                seed_phrase=encrypted_seed,
                public_key=address
            )
            Wallet.objects.create(
                user=user,
                token_type='TON',
                contract_address=address
            )

        return Response({
            "contract_address": address,
            "private_key": private_key,
            "warning": "ESTA É A ÚNICA VEZ QUE A CHAVE PRIVADA SERÁ EXIBIDA! GUARDE COM SEGURANÇA!"
        }, status=status.HTTP_201_CREATED)


class ImportWalletView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            required_fields = {'email', 'password', 'seed_phrase'}
            if missing := required_fields - set(data.keys()):
                return Response(
                    {"error": f"Campos obrigatórios faltando: {', '.join(missing)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            seed_phrase = data['seed_phrase']
            if not validate_seed_phrase(seed_phrase):
                return Response({"error": "Seed phrase inválida"}, status=status.HTTP_400_BAD_REQUEST)

            public_key, address = derive_keys_and_address(seed_phrase)

            if User.objects.filter(public_key=public_key).exists():
                return Response({"error": "Carteira já registrada"}, status=status.HTTP_409_CONFLICT)

            with transaction.atomic():
                user = User.objects.create_user(
                    email=data['email'].lower().strip(),
                    password=data['password'],
                    seed_phrase=encrypt_seed(seed_phrase),
                    public_key=public_key
                )
                Wallet.objects.create(
                    user=user,
                    token_type='TON',
                    contract_address=address
                )

            return Response({
                "public_key": public_key,
                "contract_address": address,
                "message": "Carteira importada com sucesso",
                "warning": "Guarde suas credenciais com segurança!"
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.exception("Erro em ImportWalletView")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        return Response({
            "description": "Importe uma carteira TON existente usando email, senha e seed phrase",
            "instruções": {
                "1": "Forneça email, senha e seed phrase válida",
                "2": "A seed phrase deve conter 24 palavras no formato BIP-39",
                "3": "A chave pública e o address serão gerados automaticamente"
            }
        })


class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        private_key = request.data.get('private_key')

        if not email or not private_key:
            return Response({"error": "Email e chave privada são obrigatórios"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            decrypted = decrypt_seed(user.seed_phrase)

            if private_key != decrypted:
                return Response({"error": "Chave privada inválida"}, status=status.HTTP_401_UNAUTHORIZED)

            token = create_jwt_token(user)
            return Response({
                "token": token,
                "public_key": user.public_key,
                "email": user.email
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "Usuário não encontrado"}, status=status.HTTP_404_NOT_FOUND)


class WalletView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        wallets = request.user.wallets.all()
        transactions = Transaction.objects.filter(
            Q(sender=request.user) | Q(receiver=request.user)
        ).order_by('-timestamp')[:50]

        return Response({
            "public_key": request.user.public_key,
            "wallets": WalletSerializer(wallets, many=True).data,
            "transactions": TransactionSerializer(transactions, many=True).data
        })


class SendTransactionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        receiver = request.data.get('receiver')
        amount = Decimal(request.data.get('amount'))
        token_type = request.data.get('token', 'TON')

        try:
            wallet = request.user.wallets.get(token_type=token_type)
            if wallet.balance < amount:
                return Response({"error": "Saldo insuficiente"}, status=status.HTTP_400_BAD_REQUEST)

            tx_data = {
                "from": request.user.public_key,
                "to": receiver,
                "amount": str(amount),
                "timestamp": int(time.time())
            }

            signature = sign_transaction(decrypt_seed(request.user.seed_phrase), tx_data)
            result = broadcast_transaction(tx_data, signature)

            Transaction.objects.create(
                sender=request.user,
                receiver=User.objects.get(public_key=receiver),
                amount=amount,
                token=token_type,
                tx_hash=result.get('hash'),
                status='pending'
            )

            return Response({"tx_hash": result.get('hash')}, status=status.HTTP_200_OK)

        except BlockchainError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "Destinatário não encontrado"}, status=status.HTTP_404_NOT_FOUND)


class TonWebhook(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            event = request.data.get('event')
            if not event:
                return Response({"error": "Evento não fornecido"}, status=status.HTTP_400_BAD_REQUEST)

            logger.info(f"Evento recebido: {event.get('type')} com dados: %s", event.get('data'))

            if event.get('type') == 'transaction':
                self.handle_transaction(event.get('data'))

            return Response({"status": "processed"}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("Erro ao processar webhook")
            return Response({"error": "Erro interno"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def handle_transaction(self, data):
        try:
            tx_hash = data.get('hash')
            status_update = data.get('status', 'confirmed')

            if not tx_hash:
                logger.error("Hash da transação ausente nos dados recebidos")
                return

            transaction = Transaction.objects.filter(tx_hash=tx_hash).first()

            if not transaction:
                logger.warning(f"Transação com hash {tx_hash} não encontrada")
                return

            transaction.status = status_update
            transaction.save()

            logger.info(f"Transação {tx_hash} atualizada para status: {status_update}")

        except Exception:
            logger.exception("Erro ao atualizar a transação no handle_transaction")
