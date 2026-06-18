from sqlalchemy import text

from app import AppSession, AuditSession
from app.config import Config


CERTIFICATE_COLUMNS = {
    'group_id': 'ADD COLUMN group_id INT NULL',
    'issuer': 'ADD COLUMN issuer VARCHAR(500) NULL',
    'source': "ADD COLUMN source VARCHAR(30) NULL DEFAULT 'issued'",
    'source_format': 'ADD COLUMN source_format VARCHAR(20) NULL',
    'original_filename': 'ADD COLUMN original_filename VARCHAR(255) NULL',
    'imported_at': 'ADD COLUMN imported_at DATETIME NULL',
}


APP_INDEXES = {
    'idx_certificates_status_not_after': (
        'certificates',
        'CREATE INDEX idx_certificates_status_not_after ON certificates (status, not_after)'
    ),
    'idx_certificates_group_not_after': (
        'certificates',
        'CREATE INDEX idx_certificates_group_not_after ON certificates (group_id, not_after)'
    ),
    'idx_certificates_fingerprint': (
        'certificates',
        'CREATE INDEX idx_certificates_fingerprint ON certificates (fingerprint)'
    ),
    'idx_certificates_request_id': (
        'certificates',
        'CREATE INDEX idx_certificates_request_id ON certificates (request_id)'
    ),
    'idx_certificate_requests_status_created': (
        'certificate_requests',
        'CREATE INDEX idx_certificate_requests_status_created ON certificate_requests (status, created_at)'
    ),
    'idx_certificate_downloads_certificate_created': (
        'certificate_downloads',
        'CREATE INDEX idx_certificate_downloads_certificate_created ON certificate_downloads (certificate_id, created_at)'
    ),
    'idx_certificate_downloads_user_created': (
        'certificate_downloads',
        'CREATE INDEX idx_certificate_downloads_user_created ON certificate_downloads (user_id, created_at)'
    ),
    'idx_certificate_downloads_created_at': (
        'certificate_downloads',
        'CREATE INDEX idx_certificate_downloads_created_at ON certificate_downloads (created_at)'
    ),
    'idx_user_groups_group_id': (
        'user_groups',
        'CREATE INDEX idx_user_groups_group_id ON user_groups (group_id)'
    ),
    'idx_group_permissions_permission_id': (
        'group_permissions',
        'CREATE INDEX idx_group_permissions_permission_id ON group_permissions (permission_id)'
    ),
}


AUDIT_INDEXES = {
    'idx_logs_timestamp': (
        'logs_certificadora',
        'CREATE INDEX idx_logs_timestamp ON logs_certificadora (timestamp_utc, id)'
    ),
    'idx_logs_severity_time': (
        'logs_certificadora',
        'CREATE INDEX idx_logs_severity_time ON logs_certificadora (severity, timestamp_utc)'
    ),
    'idx_logs_result_time': (
        'logs_certificadora',
        'CREATE INDEX idx_logs_result_time ON logs_certificadora (result, timestamp_utc)'
    ),
    'idx_logs_category_time': (
        'logs_certificadora',
        'CREATE INDEX idx_logs_category_time ON logs_certificadora (event_category, timestamp_utc)'
    ),
    'idx_logs_ip_time': (
        'logs_certificadora',
        'CREATE INDEX idx_logs_ip_time ON logs_certificadora (ip_address, timestamp_utc)'
    ),
    'idx_logs_certificate_id': (
        'logs_certificadora',
        'CREATE INDEX idx_logs_certificate_id ON logs_certificadora (certificate_id)'
    ),
}


def _pending_runtime_schema_items(db):
    pending = []

    if not _table_exists(db, 'certificate_groups'):
        pending.append('certificadora_db.certificate_groups')

    if not _table_exists(db, 'certificates'):
        pending.append('certificadora_db.certificates')
        return pending

    for column_name in CERTIFICATE_COLUMNS:
        if not _column_exists(db, 'certificates', column_name):
            pending.append(f'certificadora_db.certificates.{column_name}')

    return pending


def _raise_pending_migration(pending):
    items = ', '.join(pending)
    raise RuntimeError(
        'Schema do banco operacional incompleto. '
        'Execute scripts/sql/2026-06-15-schema-monitoring.sql com o usuário '
        'de migration antes de iniciar a aplicação. '
        'Não conceda CREATE, ALTER ou INDEX ao usuário runtime. '
        f'Itens pendentes: {items}'
    )


def _column_exists(db, table_name, column_name):
    sql = text(
        '''
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = :table_name
          AND COLUMN_NAME = :column_name
        LIMIT 1
        '''
    )
    return db.execute(sql, {'table_name': table_name, 'column_name': column_name}).first() is not None


def _table_exists(db, table_name):
    sql = text(
        '''
        SELECT 1
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = :table_name
        LIMIT 1
        '''
    )
    return db.execute(sql, {'table_name': table_name}).first() is not None


def _index_exists(db, table_name, index_name):
    sql = text(
        '''
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = :table_name
          AND INDEX_NAME = :index_name
        LIMIT 1
        '''
    )
    return db.execute(sql, {'table_name': table_name, 'index_name': index_name}).first() is not None


def _ensure_indexes(db, indexes):
    for index_name, (table_name, ddl) in indexes.items():
        if _table_exists(db, table_name) and not _index_exists(db, table_name, index_name):
            db.execute(text(ddl))


def ensure_certificate_monitoring_schema():
    db = AppSession()

    if not Config.DB_SCHEMA_AUTO_MIGRATE:
        pending = _pending_runtime_schema_items(db)
        if pending:
            _raise_pending_migration(pending)
        return

    db.execute(
        text(
            '''
            CREATE TABLE IF NOT EXISTS certificate_groups (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(120) NOT NULL UNIQUE,
                description TEXT NULL,
                created_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            '''
        )
    )

    for column_name, ddl in CERTIFICATE_COLUMNS.items():
        if not _column_exists(db, 'certificates', column_name):
            db.execute(text(f'ALTER TABLE certificates {ddl}'))

    _ensure_indexes(db, APP_INDEXES)
    db.commit()

    audit_db = AuditSession()
    _ensure_indexes(audit_db, AUDIT_INDEXES)
    audit_db.commit()
