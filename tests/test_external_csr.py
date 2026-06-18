import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask
from flask_login import LoginManager
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.certificates.service import (
    CertificateSigningRequestInvalid,
    extract_external_csr_metadata,
    issue_external_csr,
)
from app.certificates import routes
from app.config import Config
from app.models import CertificateRequest


def _view(fn):
    return fn.__wrapped__.__wrapped__


def _key(size=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def _csr(common_name='device.example.com', key=None):
    key = key or _key()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, 'BR'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Organization'),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName('www.device.example.com'),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _ca_material(tmpdir):
    ca_key = _key()
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'CA Interna Teste'),
            ])
        )
        .issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'CA Interna Teste'),
            ])
        )
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_path = os.path.join(tmpdir, 'ca.crt')
    ca_key_path = os.path.join(tmpdir, 'ca.key')

    with open(ca_cert_path, 'wb') as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    with open(ca_key_path, 'wb') as f:
        f.write(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    return ca_cert_path, ca_key_path


class ExternalCsrTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original_project_root = Config.PROJECT_ROOT
        self.original_storage_root = Config.STORAGE_ROOT
        self.original_cert_storage_dir = Config.CERT_STORAGE_DIR
        self.original_ca_cert_path = Config.CA_CERT_PATH
        self.original_ca_key_path = Config.CA_KEY_PATH

        Config.PROJECT_ROOT = self.tmp.name
        Config.STORAGE_ROOT = 'storage'
        Config.CERT_STORAGE_DIR = 'storage/certificates'
        Config.CA_CERT_PATH, Config.CA_KEY_PATH = _ca_material(self.tmp.name)

    def tearDown(self):
        Config.PROJECT_ROOT = self.original_project_root
        Config.STORAGE_ROOT = self.original_storage_root
        Config.CERT_STORAGE_DIR = self.original_cert_storage_dir
        Config.CA_CERT_PATH = self.original_ca_cert_path
        Config.CA_KEY_PATH = self.original_ca_key_path
        self.tmp.cleanup()

    def test_extract_external_csr_metadata_reads_subject_and_san(self):
        meta = extract_external_csr_metadata(_csr())

        self.assertEqual(meta['common_name'], 'device.example.com')
        self.assertEqual(meta['organization'], 'Example Organization')
        self.assertEqual(meta['key_algorithm'], 'RSA 2048')
        self.assertIn('www.device.example.com', meta['san_json']['dns'])

    def test_external_csr_rejects_weak_rsa_key(self):
        with self.assertRaises(CertificateSigningRequestInvalid):
            extract_external_csr_metadata(_csr(key=_key(1024)))

    def test_issue_external_csr_writes_certificate_and_csr_without_private_key(self):
        req = SimpleNamespace(
            id=77,
            csr_pem=_csr('firewall.example.com'),
            validity_days=90,
        )

        with patch('app.certificates.service.audit_log'):
            meta = issue_external_csr(req, 77)

        self.assertIsNone(meta['key_path'])
        self.assertEqual(meta['algorithm'], 'RSA 2048')
        self.assertTrue(os.path.exists(Config.resolve_path(meta['cert_path'])))
        self.assertTrue(os.path.exists(Config.resolve_path(meta['csr_path'])))

        with open(Config.resolve_path(meta['cert_path']), 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        self.assertEqual(
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'firewall.example.com'
        )
        self.assertFalse(
            cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )

    def test_external_csr_request_route_creates_pending_request(self):
        app = Flask(__name__, template_folder='../app/templates', static_folder='../app/static')
        app.config.update(SECRET_KEY='test', TESTING=True)
        app.jinja_env.globals['csrf_token'] = lambda: 'csrf-test-token'
        app.register_blueprint(routes.bp)
        login_manager = LoginManager()
        login_manager.init_app(app)

        class FakeDB:
            def __init__(self):
                self.added = []
                self.committed = False

            def add(self, row):
                row.id = 88
                self.added.append(row)

            def commit(self):
                self.committed = True

        db = FakeDB()

        with (
            patch.object(routes, 'AppSession', return_value=db),
            patch.object(routes, 'audit_log'),
            patch.object(routes, 'current_user', SimpleNamespace(id=123)),
            app.test_request_context(
                '/certificates/request/external-csr',
                method='POST',
                data={
                    'csr_pem': _csr('camera.example.com'),
                    'validity_days': '180',
                    'cert_type': 'Camera IP',
                    'environment': 'Producao',
                },
            )
        ):
            response = _view(routes.external_csr_request)()

        self.assertEqual(response.status_code, 302)
        self.assertTrue(db.committed)
        self.assertEqual(len(db.added), 1)
        self.assertIsInstance(db.added[0], CertificateRequest)
        self.assertEqual(db.added[0].common_name, 'camera.example.com')
        self.assertFalse(db.added[0].generated_by_system)
        self.assertEqual(db.added[0].status, 'pending')


if __name__ == '__main__':
    unittest.main()


