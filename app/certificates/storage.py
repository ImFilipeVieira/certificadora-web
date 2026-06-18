import os
from pathlib import Path

from app.config import Config


def _clean_part(value):
    text = str(value or '').strip().strip('/\\')

    if not text:
        raise ValueError('Parte de caminho vazia.')

    parts = text.replace('\\', '/').split('/')

    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('Parte de caminho invalida.')

    return '/'.join(parts)


def _is_relative_to(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class CertificateArtifactStorage:
    def stored_path(self, *parts):
        base = Config.STORAGE_ROOT or 'storage'
        clean_parts = [_clean_part(part) for part in parts]

        if os.path.isabs(base):
            return os.path.join(base, *clean_parts)

        return '/'.join([_clean_part(base), *clean_parts])

    def issued_paths(self, request_id):
        request_key = _clean_part(request_id)

        return {
            'cert_path': self.stored_path(
                'certificates',
                'issued',
                'requests',
                request_key,
                'certificate.crt'
            ),
            'key_path': self.stored_path(
                'private-keys',
                'issued',
                'requests',
                request_key,
                'private_key.pem.enc'
            ),
            'csr_path': self.stored_path(
                'csr',
                'issued',
                'requests',
                request_key,
                'request.csr'
            ),
        }

    def imported_certificate_path(self, fingerprint):
        return self.stored_path(
            'certificates',
            'imported',
            _clean_part(fingerprint),
            'certificate.crt'
        )

    def write_bytes(self, stored_path, data):
        real_path = self.resolve_for_write(stored_path)
        os.makedirs(os.path.dirname(real_path), exist_ok=True)

        with open(real_path, 'wb') as f:
            f.write(data)

        return real_path

    def resolve_for_write(self, stored_path):
        real_path = Path(Config.resolve_path(stored_path)).resolve()

        if not self._is_allowed_storage_path(real_path):
            raise ValueError('Caminho de storage fora da raiz permitida.')

        return str(real_path)

    def resolve_existing(self, stored_path):
        if not stored_path:
            return None

        for candidate in self._candidate_paths(stored_path):
            if candidate.exists() and self._is_allowed_storage_path(candidate):
                return str(candidate)

        return None

    def _candidate_paths(self, stored_path):
        raw_path = Path(str(stored_path))

        if raw_path.is_absolute():
            candidates = [raw_path]
        else:
            candidates = [
                Path(Config.resolve_path(str(stored_path))),
                Path.cwd() / str(stored_path),
            ]

        resolved = []

        for candidate in candidates:
            current = candidate.resolve()

            if current not in resolved:
                resolved.append(current)

        return resolved

    def _allowed_roots(self):
        roots = [
            Path(Config.resolve_path(Config.STORAGE_ROOT or 'storage')).resolve(),
            Path(Config.resolve_path(Config.CERT_STORAGE_DIR)).resolve(),
        ]

        unique_roots = []

        for root in roots:
            if root not in unique_roots:
                unique_roots.append(root)

        return unique_roots

    def _is_allowed_storage_path(self, path):
        return any(_is_relative_to(path, root) for root in self._allowed_roots())


certificate_storage = CertificateArtifactStorage()
