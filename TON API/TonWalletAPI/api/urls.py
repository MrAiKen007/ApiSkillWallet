from django.urls import path
from .views import (
    RegisterView,
    ImportWalletView,
    LoginView,
    WalletView,
    SendTransactionView,
    TonWebhook,
    api_root
)

urlpatterns = [
    # Rota raiz da API
    path('', api_root, name='api-root'),
    
    # Autenticação
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/import/', ImportWalletView.as_view(), name='import-wallet'),
    path('auth/login/', LoginView.as_view(), name='login'),
    
    # Carteira
    path('wallet/', WalletView.as_view(), name='wallet'),
    path('wallet/send/', SendTransactionView.as_view(), name='send-transaction'),
    
    # Webhook
    path('ton/webhook/', TonWebhook.as_view(), name='ton-webhook'),
]