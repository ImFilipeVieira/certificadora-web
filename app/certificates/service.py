import ipaddress
import re
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.audit.logger import audit_log
from app.config import Config
from app.certificates.storage import certificate_storage


def validate_dns(v):
    return bool(re.match(r'^(?=.{1,253}$)([A-Za-z0-9*-]{1,63}\.)*[A-Za-z0-9*-]{1,63}$', v))


class CertificateAuthorityUnavailable(RuntimeError):
    pass


class CertificateSigningRequestInvalid(ValueError):
    pass


def _name_attr(name, oid):
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _public_key_algorithm(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return f'RSA {public_key.key_size}'

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f'ECDSA {public_key.curve.name}'

    return public_key.__class__.__name__.replace('PublicKey', '')


def _validate_csr_public_key(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise CertificateSigningRequestInvalid(
                'CSR usa chave RSA menor que 2048 bits.'
            )
        return

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        allowed_curves = {'secp256r1', 'secp384r1', 'secp521r1'}
        if public_key.curve.name not in allowed_curves:
            raise CertificateSigningRequestInvalid(
                'CSR usa curva ECDSA não aprovada.'
            )
        return

    raise CertificateSigningRequestInvalid(
        'CSR usa algoritmo de chave pública não suportado.'
    )


def _load_external_csr(csr_pem):
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except ValueError as exc:
        raise CertificateSigningRequestInvalid(
            'Conteúdo informado não é uma CSR PEM válida.'
        ) from exc

    if not csr.is_signature_valid:
        raise CertificateSigningRequestInvalid(
            'Assinatura interna da CSR inválida.'
        )

    common_name = _name_attr(csr.subject, NameOID.COMMON_NAME)

    if not common_name:
        raise CertificateSigningRequestInvalid(
            'CSR sem Common Name obrigatório.'
        )

    _validate_csr_public_key(csr.public_key())

    return csr


def extract_external_csr_metadata(csr_pem):
    csr = _load_external_csr(csr_pem)
    subject = csr.subject
    public_key = csr.public_key()

    san_json = {'dns': [], 'ip': [], 'email': [], 'uri': []}
    try:
        san_ext = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        san = san_ext.value
        san_json['dns'] = list(san.get_values_for_type(x509.DNSName))
        san_json['email'] = list(san.get_values_for_type(x509.RFC822Name))
        san_json['uri'] = list(san.get_values_for_type(x509.UniformResourceIdentifier))
        san_json['ip'] = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    return {
        'common_name': _name_attr(subject, NameOID.COMMON_NAME),
        'organization': _name_attr(subject, NameOID.ORGANIZATION_NAME),
        'org_unit': _name_attr(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        'country': _name_attr(subject, NameOID.COUNTRY_NAME),
        'state': _name_attr(subject, NameOID.STATE_OR_PROVINCE_NAME),
        'locality': _name_attr(subject, NameOID.LOCALITY_NAME),
        'email': _name_attr(subject, NameOID.EMAIL_ADDRESS),
        'key_algorithm': _public_key_algorithm(public_key),
        'rsa_key_size': public_key.key_size if isinstance(public_key, rsa.RSAPublicKey) else None,
        'ecdsa_curve': public_key.curve.name if isinstance(public_key, ec.EllipticCurvePublicKey) else None,
        'san_json': san_json,
    }


def _read_ca_file(path, label, request_id):
    resolved_path = Config.resolve_path(path)

    try:
        with open(resolved_path, 'rb') as f:
            return f.read()
    except OSError:
        audit_log(
            'certificate_issue_ca_unavailable',
            'certificates',
            'error',
            'Arquivo da CA indisponível para emissão',
            request_id=request_id,
            result='failure',
            reason=f'{label}_unavailable',
            details={
                'configured_path': path
            }
        )
        raise CertificateAuthorityUnavailable(
            'Arquivos da CA indisponíveis para emissão.'
        )


def _load_ca_material(request_id):
    cert_data = _read_ca_file(Config.CA_CERT_PATH, 'ca_cert', request_id)
    key_data = _read_ca_file(Config.CA_KEY_PATH, 'ca_key', request_id)

    try:
        ca_cert = x509.load_pem_x509_certificate(cert_data)
        ca_key = serialization.load_pem_private_key(key_data, password=None)
    except (TypeError, ValueError):
        audit_log(
            'certificate_issue_ca_invalid',
            'certificates',
            'error',
            'Material da CA inválido para emissão',
            request_id=request_id,
            result='failure'
        )
        raise CertificateAuthorityUnavailable(
            'Arquivos da CA inválidos para emissão.'
        )

    return ca_cert, ca_key


def issue_certificate(req, cert_id_hint):
    audit_log(
        'certificate_issue_started',
        'certificates',
        'info',
        'Emissão iniciada',
        request_id=req.id
    )

    ca_cert, ca_key = _load_ca_material(req.id)

    key = (
        rsa.generate_private_key(
            public_exponent=65537,
            key_size=req.rsa_key_size or 2048
        )
        if req.key_algorithm != 'ECDSA'
        else ec.generate_private_key(ec.SECP256R1())
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, req.country or 'BR'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, req.state or 'MG'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, req.locality or ''),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, req.organization or ''),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, req.org_unit or ''),
        x509.NameAttribute(NameOID.COMMON_NAME, req.common_name),
    ])

    serial = x509.random_serial_number()
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=req.validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
    )

    san = []
    for d in (req.san_json or {}).get('dns', []):
        san.append(x509.DNSName(d))
    for ip in (req.san_json or {}).get('ip', []):
        san.append(x509.IPAddress(ipaddress.ip_address(ip)))
    for e in (req.san_json or {}).get('email', []):
        san.append(x509.RFC822Name(e))
    for u in (req.san_json or {}).get('uri', []):
        san.append(x509.UniformResourceIdentifier(u))

    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san),
            critical=False
        )

    cert = builder.sign(ca_key, hashes.SHA256())

    paths = certificate_storage.issued_paths(cert_id_hint)
    cert_path = paths['cert_path']
    key_path = paths['key_path']
    csr_path = paths['csr_path']

    certificate_storage.write_bytes(
        cert_path,
        cert.public_bytes(serialization.Encoding.PEM)
    )

    certificate_storage.write_bytes(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(
                Config.SECRET_KEY.encode()[:32] or b'change-me'
            )
        )
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        key,
        hashes.SHA256()
    )

    certificate_storage.write_bytes(
        csr_path,
        csr.public_bytes(serialization.Encoding.PEM)
    )

    fp = cert.fingerprint(hashes.SHA256()).hex()
    audit_log(
        'certificate_issue_success',
        'certificates',
        'info',
        'Certificado emitido',
        request_id=req.id,
        certificate_serial=str(serial),
        certificate_fingerprint=fp,
        result='success'
    )

    return {
        'serial': str(serial),
        'fingerprint': fp,
        'issuer': ca_cert.subject.rfc4514_string(),
        'cert_path': cert_path,
        'key_path': key_path,
        'csr_path': csr_path,
        'not_before': cert.not_valid_before_utc.replace(tzinfo=None),
        'not_after': cert.not_valid_after_utc.replace(tzinfo=None),
    }


def issue_external_csr(req, cert_id_hint):
    audit_log(
        'external_csr_issue_started',
        'certificates',
        'info',
        'Assinatura de CSR externa iniciada',
        request_id=req.id
    )

    ca_cert, ca_key = _load_ca_material(req.id)
    csr = _load_external_csr(req.csr_pem or '')
    now = datetime.now(timezone.utc)
    serial = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=req.validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_cert.public_key()
            ),
            critical=False
        )
    )

    for extension in csr.extensions:
        if isinstance(extension.value, x509.BasicConstraints):
            continue
        if isinstance(extension.value, x509.SubjectKeyIdentifier):
            continue
        if isinstance(extension.value, x509.AuthorityKeyIdentifier):
            continue
        builder = builder.add_extension(
            extension.value,
            critical=extension.critical
        )

    cert = builder.sign(ca_key, hashes.SHA256())
    paths = certificate_storage.issued_paths(cert_id_hint)
    cert_path = paths['cert_path']
    csr_path = paths['csr_path']

    certificate_storage.write_bytes(
        cert_path,
        cert.public_bytes(serialization.Encoding.PEM)
    )

    certificate_storage.write_bytes(
        csr_path,
        csr.public_bytes(serialization.Encoding.PEM)
    )

    fp = cert.fingerprint(hashes.SHA256()).hex()
    audit_log(
        'external_csr_issue_success',
        'certificates',
        'info',
        'CSR externa assinada',
        request_id=req.id,
        certificate_serial=str(serial),
        certificate_fingerprint=fp,
        result='success'
    )

    return {
        'serial': str(serial),
        'fingerprint': fp,
        'issuer': ca_cert.subject.rfc4514_string(),
        'cert_path': cert_path,
        'key_path': None,
        'csr_path': csr_path,
        'not_before': cert.not_valid_before_utc.replace(tzinfo=None),
        'not_after': cert.not_valid_after_utc.replace(tzinfo=None),
        'algorithm': _public_key_algorithm(csr.public_key()),
    }
