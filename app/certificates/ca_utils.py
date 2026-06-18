import os
import stat

from app.audit.logger import audit_log
from app.config import Config


def check_ca_files():
    for p in [Config.CA_CERT_PATH, Config.CA_KEY_PATH, Config.CA_SERIAL_PATH]:
        resolved_path = Config.resolve_path(p)

        if not os.path.exists(resolved_path):
            audit_log(
                'ca_file_missing',
                'system',
                'error',
                f'Arquivo da CA ausente: {p}',
                resource_type='ca_file',
                resource_name=p
            )
            continue

        mode = stat.S_IMODE(os.stat(resolved_path).st_mode)

        if p.endswith('.key') and mode & 0o077:
            audit_log(
                'ca_file_permission_warning',
                'system',
                'warning',
                f'Permissao insegura: {oct(mode)}',
                resource_type='ca_file',
                resource_name=p
            )

    audit_log('ca_files_checked', 'system', 'info', 'Arquivos da CA verificados')
