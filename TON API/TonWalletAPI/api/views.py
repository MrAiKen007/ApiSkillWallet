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
from django.conf import settings

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from django.shortcuts import get_object_or_404, render, redirect


# Importa o cliente TON e utilitários de criptografia (ajuste as importações conforme sua biblioteca)
from .clients.ton_client import PyTONClient      # Cliente PyTONClient para interação com a TON blockchain
from .utils import decrypt_seed, derive_keys_and_address  # Funções para descriptografar a seed e derivar chaves/endereço

from .models import User, Wallet, Transaction
from .serializers import WalletSerializer, TransactionSerializer
from .utils import (
    generate_seed_phrase,
    encrypt_seed,
    decrypt_seed,
    sign_transaction,
    broadcast_transaction,
    validate_seed_phrase,
    derive_keys_and_address,
    BlockchainError
)
from decimal import Decimal
import time
import logging

from api.clients.ton_client import PyTONClient

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

        try:
            seed_phrase = generate_seed_phrase()
            keys = derive_keys_and_address(' '.join(seed_phrase))
            encrypted_seed = encrypt_seed(' '.join(seed_phrase))

            with transaction.atomic():
                user = User.objects.create_user(
                    email=email,
                    password=password,
                    seed_phrase=encrypted_seed,
                    public_key=keys['public_key']
                )
                Wallet.objects.create(
                    user=user,
                    token_type='TON',
                    contract_address=keys['address']
                )

            return Response({
                "address": keys['address'],
                "seed_phrase": ' '.join(seed_phrase),
                "warning": "GUARDE ESTA SEED PHRASE COM SEGURANÇA! ELA NÃO SERÁ EXIBIDA NOVAMENTE!"
            }, status=status.HTTP_201_CREATED)

        except BlockchainError as e:
            logger.exception("Erro na blockchain")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception:
            logger.exception("Erro geral")
            return Response({"error": "Falha interna no servidor"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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

            keys = derive_keys_and_address(seed_phrase)

            if User.objects.filter(public_key=keys['public_key']).exists():
                return Response({"error": "Carteira já registrada"}, status=status.HTTP_409_CONFLICT)

            with transaction.atomic():
                user = User.objects.create_user(
                    email=data['email'].lower().strip(),
                    password=data['password'],
                    seed_phrase=encrypt_seed(seed_phrase),
                    public_key=keys['public_key']
                )
                Wallet.objects.create(
                    user=user,
                    token_type='TON',
                    contract_address=keys['address']
                )

            return Response({
                "public_key": keys['public_key'],
                "address": keys['address'],
                "message": "Carteira importada com sucesso"
            }, status=status.HTTP_201_CREATED)

        except BlockchainError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            logger.exception("Erro em ImportWalletView")
            return Response({"error": "Erro interno"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email e senha são obrigatórios"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            if not user.check_password(password):
                return Response({"error": "Credenciais inválidas"}, status=status.HTTP_401_UNAUTHORIZED)

            token = create_jwt_token(user)
            return Response({
                "token": token,
                "public_key": user.public_key,
                "email": user.email
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "Usuário não encontrado"}, status=status.HTTP_404_NOT_FOUND)


class WalletView(APIView):
    """
    API para exibir o endereço e saldo da carteira TON do usuário logado.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        wallet = get_object_or_404(Wallet, user=user)
        address = wallet.contract_address  # Endereço salvo no banco

        # Consulta saldo via API HTTP pública
        import requests
        from django.conf import settings
        url = f"{settings.TON_API_URL}?address={address}"
        try:
            response = requests.get(url)
            data = response.json()
            if 'result' in data and 'balance' in data['result']:
                balance = int(data['result']['balance']) / 1e9
                return Response({
                    'address': address,
                    'balance': f"{balance:.9f}",
                    'token_name': 'Toncoin',
                    'token_symbol': 'TON'
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Saldo não encontrado ou endereço não ativado.'}, status=404)
        except Exception as e:
            import logging
            logging.exception(f"Erro ao consultar saldo: {e}")
            return Response({'error': 'Erro ao consultar saldo.'}, status=500)


class SendTransactionView(APIView):
    """
    API para enviar transações na blockchain TON.
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        user = request.user
        receiver_address = request.data.get('receiver')
        amount_str = request.data.get('amount')

        if not receiver_address or not amount_str:
            return Response({'error': 'Endereço e valor são obrigatórios.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount_decimal = Decimal(amount_str)
            amount_nano = int(amount_decimal * Decimal(10**9))
        except:
            return Response({'error': 'Valor inválido.'}, status=status.HTTP_400_BAD_REQUEST)

        receiver_user = get_object_or_404(User, public_key=receiver_address)
        wallet = get_object_or_404(Wallet, user=user)
        encrypted_seed = user.seed_phrase
        
        # Tenta descriptografar com a senha do usuário
        try:
            seed_phrase = decrypt_seed(encrypted_seed, user.password)
        except BlockchainError:
            # Se falhar, tenta sem senha
            seed_phrase = decrypt_seed(encrypted_seed)
            
        keys = derive_keys_and_address(seed_phrase)
        sender_address = keys.get('address') if isinstance(keys, dict) else keys[0]
        secret_key = keys.get('secret') if isinstance(keys, dict) else keys[1]

        client = PyTONClient()
        signed_tx = client.sign_transaction(sender_address, receiver_address, amount_nano, secret_key)
        broadcast_result = client.broadcast_transaction(signed_tx)
        tx_hash = broadcast_result if isinstance(broadcast_result, str) else broadcast_result.get('transactionHash')

        Transaction.objects.create(
            sender=user,
            receiver=receiver_user,
            amount=amount_decimal,
            transaction_hash=tx_hash
        )

        return Response({
            'message': 'Transação enviada com sucesso.',
            'transaction_hash': tx_hash
        }, status=status.HTTP_200_OK)

class TonWebhook(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            event = request.data.get('event')
            if not event:
                return Response({"error": "Evento não fornecido"}, status=status.HTTP_400_BAD_REQUEST)

            logger.info(f"Evento recebido: {event.get('type')}")

            if event.get('type') == 'transaction':
                self.handle_transaction(event.get('data'))

            return Response({"status": "processed"}, status=status.HTTP_200_OK)

        except Exception:
            logger.exception("Erro ao processar webhook")
            return Response({"error": "Erro interno"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def handle_transaction(self, data):
        try:
            tx_hash = data.get('hash')
            status_update = data.get('status', 'confirmed')

            transaction = Transaction.objects.filter(tx_hash=tx_hash).first()
            if transaction:
                transaction.status = status_update
                transaction.save()
                logger.info(f"Transação {tx_hash} atualizada para {status_update}")

        except Exception as e:
            logger.error(f"Erro ao atualizar transação: {str(e)}")