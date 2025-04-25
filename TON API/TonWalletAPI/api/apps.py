from django.apps import AppConfig

class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'
    verbose_name = 'API Module'

    def ready(self):
        # Força o registro do modelo User
        from .models import User
        super().ready()