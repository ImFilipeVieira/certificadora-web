import os
import tempfile
import unittest
from pathlib import Path

from app.certificates.storage import certificate_storage
from app.config import Config


class CertificateArtifactStorageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original_project_root = Config.PROJECT_ROOT
        self.original_storage_root = Config.STORAGE_ROOT
        self.original_cert_storage_dir = Config.CERT_STORAGE_DIR

        Config.PROJECT_ROOT = self.tmp.name
        Config.STORAGE_ROOT = 'storage'
        Config.CERT_STORAGE_DIR = 'storage/certificates'

    def tearDown(self):
        Config.PROJECT_ROOT = self.original_project_root
        Config.STORAGE_ROOT = self.original_storage_root
        Config.CERT_STORAGE_DIR = self.original_cert_storage_dir
        self.tmp.cleanup()

    def test_issued_paths_use_reorganized_layout(self):
        paths = certificate_storage.issued_paths(42)

        self.assertEqual(
            paths['cert_path'],
            'storage/certificates/issued/requests/42/certificate.crt'
        )
        self.assertEqual(
            paths['key_path'],
            'storage/private-keys/issued/requests/42/private_key.pem.enc'
        )
        self.assertEqual(
            paths['csr_path'],
            'storage/csr/issued/requests/42/request.csr'
        )

    def test_imported_certificate_path_uses_fingerprint_directory(self):
        path = certificate_storage.imported_certificate_path('abc123')

        self.assertEqual(
            path,
            'storage/certificates/imported/abc123/certificate.crt'
        )

    def test_write_and_resolve_storage_path(self):
        stored_path = certificate_storage.issued_paths(7)['cert_path']
        real_path = certificate_storage.write_bytes(stored_path, b'cert-data')

        self.assertTrue(os.path.exists(real_path))
        self.assertEqual(
            certificate_storage.resolve_existing(stored_path),
            real_path
        )

    def test_legacy_certificate_storage_path_still_resolves(self):
        legacy_path = 'storage/certificates/cert_1_legacy.crt'
        real_path = Config.resolve_path(legacy_path)
        os.makedirs(os.path.dirname(real_path), exist_ok=True)

        with open(real_path, 'wb') as f:
            f.write(b'legacy-cert')

        self.assertEqual(
            certificate_storage.resolve_existing(legacy_path),
            str(Path(real_path).resolve())
        )

    def test_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            certificate_storage.stored_path('certificates', '..', 'secret.key')

        self.assertIsNone(certificate_storage.resolve_existing('../secret.key'))


if __name__ == '__main__':
    unittest.main()
