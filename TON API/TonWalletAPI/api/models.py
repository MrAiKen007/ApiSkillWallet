from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.core.validators import MinLengthValidator, RegexValidator
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('O email deve ser definido'))
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    username = None
    first_name = None
    last_name = None

    SEED_PHRASE_LENGTH = 24
    SEED_PHRASE_MAX_LENGTH = SEED_PHRASE_LENGTH * 12
    
    seed_phrase_validator = RegexValidator(
        regex=r'^[a-z]+( [a-z]+){23}$',
        message=_('Deve conter 24 palavras minúsculas separadas por espaços')
    )
    
    email = models.EmailField(
        _('email'),
        unique=True,
        help_text=_('Endereço de email único para login')
    )
    
    seed_phrase = models.CharField(
        _('seed phrase'),
        max_length=SEED_PHRASE_MAX_LENGTH,
        validators=[
            MinLengthValidator(128),
            seed_phrase_validator
        ],
        help_text=_('24 palavras secretas para recuperação da carteira')
    )
    
    public_key = models.CharField(
        _('chave pública'),
        max_length=256,
        unique=True,
        validators=[
            MinLengthValidator(64),
            RegexValidator(
                regex=r'^[0-9a-fA-F]{64,256}$',
                message=_('Formato hexadecimal inválido')
            )
        ],
        db_index=True
    )
    
    created_at = models.DateTimeField(
        _('criado em'),
        default=timezone.now,
        db_index=True
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        verbose_name = _('usuário')
        verbose_name_plural = _('usuários')
        indexes = [
            models.Index(fields=['public_key', 'email']),
        ]

    def __str__(self):
        return f"{self.email} ({self.public_key[:8]}...)"

    groups = models.ManyToManyField(
        Group,
        verbose_name=_('grupos'),
        blank=True,
        related_name='tonwallet_users',
        related_query_name='tonwallet_user'
    )
    
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('permissões'),
        blank=True,
        related_name='tonwallet_users',
        related_query_name='tonwallet_user'
    )

class Wallet(models.Model):
    class TokenType(models.TextChoices):
        TON = 'TON', _('Toncoin')
        JETTON = 'JETTON', _('Jetton')
        NFT = 'NFT', _('NFT')

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='wallets',
        verbose_name=_('usuário')
    )
    
    token_type = models.CharField(
        _('tipo de token'),
        max_length=10,
        choices=TokenType.choices,
        default=TokenType.TON
    )
    
    balance = models.DecimalField(
        _('saldo'),
        max_digits=36,
        decimal_places=9,
        default=0
    )
    
    contract_address = models.CharField(
        _('endereço do contrato'),
        max_length=256
    )
    
    class Meta:
        verbose_name = _('carteira')
        verbose_name_plural = _('carteiras')
        ordering = ['-token_type']

    def __str__(self):
        return f"{self.user} - {self.get_token_type_display()}"

class Transaction(models.Model):
    class Status(models.TextChoices):
        PENDING = 'pending', _('Pendente')
        CONFIRMED = 'confirmed', _('Confirmada')
        FAILED = 'failed', _('Falhou')

    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='sent_transactions',
        on_delete=models.CASCADE,
        verbose_name=_('remetente')
    )
    
    receiver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='received_transactions',
        on_delete=models.CASCADE,
        verbose_name=_('destinatário')
    )
    
    amount = models.DecimalField(
        _('valor'),
        max_digits=36,
        decimal_places=9
    )
    
    token = models.CharField(
        _('token'),
        max_length=10,
        choices=Wallet.TokenType.choices
    )
    
    tx_hash = models.CharField(
        _('hash da transação'),
        max_length=256,
        unique=True
    )
    
    timestamp = models.DateTimeField(
        _('data/hora'),
        auto_now_add=True
    )
    
    status = models.CharField(
        _('status'),
        max_length=10,
        choices=Status.choices,
        default=Status.PENDING
    )

    class Meta:
        verbose_name = _('transação')
        verbose_name_plural = _('transações')
        indexes = [
            models.Index(fields=['tx_hash']),
            models.Index(fields=['sender', 'receiver']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.tx_hash[:12]}... - {self.amount} {self.token}"