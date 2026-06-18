from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, Integer, BigInteger, String, Text, DateTime, Boolean, ForeignKey, JSON
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

Base = declarative_base()

APP_TIMEZONE = ZoneInfo("America/Sao_Paulo")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def localnow():
    return datetime.now(APP_TIMEZONE).replace(tzinfo=None)


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(120), unique=True, nullable=False)
    display_name = Column(String(255))
    email = Column(String(255))
    enabled = Column(Boolean, default=True)
    mfa_secret = Column(String(255))
    mfa_enabled = Column(Boolean, default=False)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)

    created_at = Column(DateTime, default=localnow)
    updated_at = Column(DateTime, default=localnow, onupdate=localnow)

    certificate_requests = relationship(
        'CertificateRequest',
        foreign_keys='CertificateRequest.requester_id',
        back_populates='requester'
    )

    approved_certificate_requests = relationship(
        'CertificateRequest',
        foreign_keys='CertificateRequest.approver_id',
        back_populates='approver'
    )

    downloads = relationship('CertificateDownload', back_populates='user')
    revocations = relationship('Revocation', back_populates='revoked_by_user')

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self.enabled

    @property
    def is_anonymous(self):
        return False


class Group(Base):
    __tablename__ = 'groups'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True)
    description = Column(Text)

    user_links = relationship('UserGroup', back_populates='group')
    permission_links = relationship('GroupPermission', back_populates='group')


class Permission(Base):
    __tablename__ = 'permissions'

    id = Column(Integer, primary_key=True)
    code = Column(String(120), unique=True)
    description = Column(Text)

    group_links = relationship('GroupPermission', back_populates='permission')


class UserGroup(Base):
    __tablename__ = 'user_groups'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    group_id = Column(Integer, ForeignKey('groups.id'))

    user = relationship('User')
    group = relationship('Group', back_populates='user_links')


class GroupPermission(Base):
    __tablename__ = 'group_permissions'

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey('groups.id'))
    permission_id = Column(Integer, ForeignKey('permissions.id'))

    group = relationship('Group', back_populates='permission_links')
    permission = relationship('Permission', back_populates='group_links')


class CertificateRequest(Base):
    __tablename__ = 'certificate_requests'

    id = Column(Integer, primary_key=True)

    requester_id = Column(Integer, ForeignKey('users.id'))
    approver_id = Column(Integer, ForeignKey('users.id'))

    requester = relationship(
        'User',
        foreign_keys=[requester_id],
        back_populates='certificate_requests'
    )

    approver = relationship(
        'User',
        foreign_keys=[approver_id],
        back_populates='approved_certificate_requests'
    )

    status = Column(String(30), default='pending')
    cert_type = Column(String(60))
    common_name = Column(String(255))
    organization = Column(String(255))
    org_unit = Column(String(255))
    country = Column(String(2))
    state = Column(String(120))
    locality = Column(String(120))
    email = Column(String(255))
    validity_days = Column(Integer)
    key_algorithm = Column(String(20))
    rsa_key_size = Column(Integer)
    ecdsa_curve = Column(String(80))
    key_usage = Column(Text)
    extended_key_usage = Column(Text)
    san_json = Column(JSON)
    justification = Column(Text)
    system_name = Column(String(255))
    environment = Column(String(60))
    technical_owner = Column(String(255))
    area = Column(String(255))
    notes = Column(Text)
    csr_pem = Column(Text)
    generated_by_system = Column(Boolean)
    approval_comment = Column(Text)
    rejection_reason = Column(Text)

    created_at = Column(DateTime, default=localnow)
    updated_at = Column(DateTime, default=localnow, onupdate=localnow)
    decided_at = Column(DateTime)


class Certificate(Base):
    __tablename__ = 'certificates'

    id = Column(Integer, primary_key=True)
    request_id = Column(Integer, ForeignKey('certificate_requests.id'))
    group_id = Column(Integer, ForeignKey('certificate_groups.id'))
    serial = Column(String(128))
    fingerprint = Column(String(128))
    common_name = Column(String(255))
    issuer = Column(String(500))
    status = Column(String(30), default='issued')
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    cert_path = Column(String(500))
    key_path = Column(String(500))
    csr_path = Column(String(500))
    algorithm = Column(String(80))
    source = Column(String(30), default='issued')
    source_format = Column(String(20))
    original_filename = Column(String(255))
    imported_at = Column(DateTime)
    created_at = Column(DateTime, default=localnow)
    revoked_at = Column(DateTime)
    revocation_reason = Column(String(80))
    revocation_comment = Column(Text)

    request = relationship('CertificateRequest')
    group = relationship('CertificateGroup', back_populates='certificates')
    downloads = relationship('CertificateDownload', back_populates='certificate')
    revocations = relationship('Revocation', back_populates='certificate')


class CertificateGroup(Base):
    __tablename__ = 'certificate_groups'

    id = Column(Integer, primary_key=True)
    name = Column(String(120), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=localnow)
    updated_at = Column(DateTime, default=localnow, onupdate=localnow)

    certificates = relationship('Certificate', back_populates='group')


class CertificateDownload(Base):
    __tablename__ = 'certificate_downloads'

    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    format = Column(String(20))
    result = Column(String(30))
    ip_address = Column(String(64))
    user_agent = Column(Text)
    created_at = Column(DateTime, default=utcnow)

    certificate = relationship('Certificate', back_populates='downloads')
    user = relationship('User', back_populates='downloads')


class Revocation(Base):
    __tablename__ = 'revocations'

    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'), nullable=False)
    reason = Column(String(80), nullable=False)
    comment = Column(Text)
    revoked_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=utcnow, nullable=False)
    revoked_at = Column(DateTime)

    certificate = relationship('Certificate', back_populates='revocations')
    revoked_by_user = relationship('User', back_populates='revocations')


class AuditLog(Base):
    __tablename__ = 'logs_certificadora'

    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    event_id = Column(String(36))
    timestamp_utc = Column(DateTime)
    timestamp_local = Column(DateTime)
    event_type = Column(String(120))
    event_category = Column(String(80))
    severity = Column(String(20))
    actor_user_id = Column(Integer)
    actor_username = Column(String(120))
    actor_display_name = Column(String(255))
    actor_groups = Column(Text)
    action = Column(String(120))
    resource_type = Column(String(80))
    resource_id = Column(String(120))
    resource_name = Column(String(255))
    request_id = Column(Integer)
    certificate_id = Column(Integer)
    certificate_serial = Column(String(128))
    certificate_fingerprint = Column(String(128))
    status_before = Column(String(80))
    status_after = Column(String(80))
    result = Column(String(30))
    reason = Column(Text)
    message = Column(Text)
    details_json = Column(JSON)
    ip_address = Column(String(64))
    forwarded_for = Column(String(255))
    user_agent = Column(Text)
    session_id = Column(String(255))
    mfa_status = Column(String(80))
    ldap_auth_result = Column(String(80))
    http_method = Column(String(20))
    endpoint = Column(String(255))
    http_status_code = Column(Integer)
    created_at = Column(DateTime, default=localnow)
