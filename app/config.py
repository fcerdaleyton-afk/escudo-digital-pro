import os


class Settings:
    """
    Configuración centralizada.
    Las variables sensibles vienen de variables de entorno.
    Las fijas están aquí para auditoría.
    """
    
    # Identidad de la aplicación
    PROJECT_NAME = os.getenv("PROJECT_NAME", "MARY_V5")
    VERSION = os.getenv("VERSION", "5.0")
    
    # Entorno: dev, staging, prod
    # IMPORTANTE: En producción DEBE estar definida como "prod"
    ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")
    
    # Validar que el entorno sea válido
    @property
    def is_production(self):
        return self.ENVIRONMENT == "prod"
    
    @property
    def is_development(self):
        return self.ENVIRONMENT == "dev"


settings = Settings()