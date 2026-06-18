import os
import ssl
from ipaddress import ip_address
from app import create_app
from app.config import Config


def is_loopback_host(host):
    if (host or '').lower() == 'localhost':
        return True

    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def validate_runtime_security():
    if Config.FLASK_DEBUG and not is_loopback_host(Config.APP_HOST):
        raise RuntimeError(
            "FLASK_DEBUG=true só é permitido com APP_HOST de loopback "
            "(127.0.0.1, ::1 ou localhost)."
        )


validate_runtime_security()
app = create_app()


def build_ssl_context():
    if not Config.WEB_SSL_ENABLED:
        return None

    cert_path = Config.resolve_path(Config.WEB_SSL_CERT_PATH)
    key_path = Config.resolve_path(Config.WEB_SSL_KEY_PATH)

    if not cert_path:
        raise RuntimeError(
            "WEB_SSL_ENABLED=true, mas WEB_SSL_CERT_PATH não foi informado no .env."
        )

    if not key_path:
        raise RuntimeError(
            "WEB_SSL_ENABLED=true, mas WEB_SSL_KEY_PATH não foi informado no .env."
        )

    if not os.path.exists(cert_path):
        raise FileNotFoundError(
            f"Certificado HTTPS não encontrado em: {cert_path}"
        )

    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"Chave privada HTTPS não encontrada em: {key_path}"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=cert_path,
        keyfile=key_path,
        password=Config.WEB_SSL_KEY_PASSWORD
    )

    return context


if __name__ == '__main__':
    ssl_context = build_ssl_context()

    protocol = 'https' if ssl_context else 'http'

    print("=" * 80)
    print("Certificadora Web")
    print(f"Servidor iniciando em: {protocol}://{Config.APP_HOST}:{Config.APP_PORT}")
    print(f"SSL habilitado: {Config.WEB_SSL_ENABLED}")
    if ssl_context:
        print(f"Certificado SSL: {Config.WEB_SSL_CERT_PATH}")
        print(f"Chave SSL: {Config.WEB_SSL_KEY_PATH}")
    print("=" * 80)

    app.run(
        host=Config.APP_HOST,
        port=Config.APP_PORT,
        debug=Config.FLASK_DEBUG,
        ssl_context=ssl_context
    )
