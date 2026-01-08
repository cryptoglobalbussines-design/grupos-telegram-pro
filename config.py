import os

class Config:
    # Clave secreta (cámbiala por algo muy largo y random, como una contraseña)
    SECRET_KEY = 'Diosesamor2511_+123Miexito@'

    # Base de datos (un archivo simple en tu carpeta)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///grupos.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ===== CONFIGURACIÓN DE EMAIL (IMPORTANTE) =====
    # Usaremos Gmail para enviar los emails de confirmación
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'alegriabtc@gmail.com'   # ⚠️ Cambia esto por TU correo real
    MAIL_PASSWORD = 'hwxn rbrn hzgb kwrz'       # ⚠️ NO uses tu contraseña normal → usa "contraseña de app"
    MAIL_DEFAULT_SENDER = 'Grupos Telegram Pro'

    # Contraseña del panel de administrador (cámbiala después)
    ADMIN_PASSWORD = '+123Miexito@'
    
    RECAPTCHA_SITE_KEY = '6LfGu0IsAAAAADZCfXbNmIkQEws8heEDwSZPMyVs'      # Pega la Site key
    RECAPTCHA_SECRET_KEY = '6LfGu0IsAAAAADoVkrfYXNjp-QbCQRfnb8vrR9QW'  # Pega la Secret key

    ADMIN_MASTER_PASSWORD = '+123Miexito@'  # Pon aquí tu contraseña maestra real (larga y única)