import os
from dotenv import load_dotenv
from sqlalchemy.engine import URL

load_dotenv()


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def as_bool(v):
    return str(v).lower() in ('1', 'true', 'yes', 'on')


class Config:
    APP_VERSION = os.getenv('APP_VERSION', '1.4.1')
    PROJECT_ROOT = PROJECT_ROOT
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-change-me')
    DEMO_MODE = as_bool(os.getenv('DEMO_MODE', 'false'))
    AUTH_PROVIDER = os.getenv('AUTH_PROVIDER', 'ldap').lower()
    MOCK_AUTH_PASSWORD = os.getenv('MOCK_AUTH_PASSWORD', '')
    MFA_REQUIRED = as_bool(os.getenv('MFA_REQUIRED', 'true'))

    LDAP_HOST = os.getenv('LDAP_HOST')
    LDAP_PORT = int(os.getenv('LDAP_PORT', '389'))
    LDAP_USE_SSL = as_bool(os.getenv('LDAP_USE_SSL', 'false'))
    LDAP_BASE_DN = os.getenv('LDAP_BASE_DN')
    LDAP_SEARCH_ATTRIBUTE = os.getenv('LDAP_SEARCH_ATTRIBUTE', 'sAMAccountName')
    LDAP_BIND_DN = os.getenv('LDAP_BIND_DN')
    LDAP_BIND_PASSWORD = os.getenv('LDAP_BIND_PASSWORD')

    MFA_ISSUER = os.getenv('MFA_ISSUER', 'Certificadora Web')

    APP_DATABASE_URI = os.getenv('APP_DATABASE_URL') or URL.create(
        'mysql+pymysql',
        username=os.getenv('APP_DB_USER'),
        password=os.getenv('APP_DB_PASSWORD'),
        host=os.getenv('APP_DB_HOST', '127.0.0.1'),
        port=int(os.getenv('APP_DB_PORT', '3306')),
        database=os.getenv('APP_DB_NAME', 'certificadora_db'),
        query={'charset': 'utf8mb4'},
    )

    AUDIT_DATABASE_URI = os.getenv('AUDIT_DATABASE_URL') or URL.create(
        'mysql+pymysql',
        username=os.getenv('AUDIT_DB_USER'),
        password=os.getenv('AUDIT_DB_PASSWORD'),
        host=os.getenv('AUDIT_DB_HOST', '127.0.0.1'),
        port=int(os.getenv('AUDIT_DB_PORT', '3306')),
        database=os.getenv('AUDIT_DB_NAME', 'audit_log'),
        query={'charset': 'utf8mb4'},
    )

    DB_SCHEMA_AUTO_MIGRATE = as_bool(os.getenv('DB_SCHEMA_AUTO_MIGRATE', 'false'))

    CA_CERT_PATH = os.getenv('CA_CERT_PATH', 'ca/example-ca.crt')
    CA_KEY_PATH = os.getenv('CA_KEY_PATH', 'ca/example-ca.key')
    CA_SERIAL_PATH = os.getenv('CA_SERIAL_PATH', 'ca/example-ca.srl')

    STORAGE_ROOT = os.getenv('STORAGE_ROOT', 'storage')
    CERT_STORAGE_DIR = os.getenv('CERT_STORAGE_DIR', 'storage/certificates')
    MAX_CERT_VALIDITY_DAYS = int(os.getenv('MAX_CERT_VALIDITY_DAYS', '825'))
    ALLOW_UNPROTECTED_PKCS12_EXPORT = as_bool(os.getenv('ALLOW_UNPROTECTED_PKCS12_EXPORT', 'false'))

    APP_HOST = os.getenv('APP_HOST', '127.0.0.1')
    APP_PORT = int(os.getenv('APP_PORT', '5000'))
    FLASK_DEBUG = as_bool(os.getenv('FLASK_DEBUG', 'false'))

    # HTTPS do servidor web
    # Estes arquivos são para publicar a aplicação em HTTPS.
    # Não confundir com CA_CERT_PATH/CA_KEY_PATH, que são usados para emissão de certificados.
    WEB_SSL_ENABLED = as_bool(os.getenv('WEB_SSL_ENABLED', 'false'))
    WEB_SSL_CERT_PATH = os.getenv('WEB_SSL_CERT_PATH', '')
    WEB_SSL_KEY_PATH = os.getenv('WEB_SSL_KEY_PATH', '')
    WEB_SSL_KEY_PASSWORD = os.getenv('WEB_SSL_KEY_PASSWORD') or None

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Quando o sistema estiver em HTTPS, força cookies seguros.
    # Se WEB_SSL_ENABLED=false, mantém compatibilidade com HTTP local.
    SESSION_COOKIE_SECURE = WEB_SSL_ENABLED

    @staticmethod
    def resolve_path(path):
        if not path or os.path.isabs(path):
            return path

        return os.path.join(Config.PROJECT_ROOT, path)

