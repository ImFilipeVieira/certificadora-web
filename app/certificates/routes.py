import os
import zipfile
import tempfile
import shutil
from datetime import date, timedelta

from flask import Blueprint, render_template, request, redirect, url_for, send_file, abort, flash
from flask_login import login_required, current_user
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from sqlalchemy import or_, func
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename

from app import AppSession
from app.models import CertificateRequest, Certificate, CertificateGroup, Revocation, localnow
from app.audit.logger import audit_log
from app.permissions.decorators import permission_required
from app.certificates.service import (
    CertificateAuthorityUnavailable,
    CertificateSigningRequestInvalid,
    extract_external_csr_metadata,
    issue_certificate,
    issue_external_csr,
)
from app.certificates.storage import certificate_storage
from app.config import Config


bp = Blueprint('certs', __name__, url_prefix='/certificates')


DEFAULT_SUBJECT = {
    'email': 'security@example.com',
    'org_unit': 'Departamento TI',
    'organization': 'Example Organization',
    'locality': 'Sao Paulo',
    'state': 'Sao Paulo',
    'country': 'BR'
}


MIME_TYPES = {
    'pem': 'application/x-pem-file',
    'crt': 'application/x-x509-ca-cert',
    'cer': 'application/pkix-cert',
    'key': 'application/octet-stream',
    'csr': 'application/pkcs10',
    'der': 'application/pkix-cert',
    'pfx': 'application/x-pkcs12',
    'p12': 'application/x-pkcs12',
    'zip': 'application/zip'
}


# Formatos bloqueados para certificados revogados.
# Mantemos formatos públicos disponíveis para auditoria/consulta:
# pem, crt, cer, der e csr.
REVOKED_BLOCKED_DOWNLOAD_FORMATS = {'key', 'pfx', 'p12', 'zip'}
IMPORT_CERTIFICATE_FORMATS = {'crt', 'cer', 'pem', 'der', 'pfx', 'p12'}
EXTERNAL_CSR_FORMATS = {'csr', 'pem', 'txt'}
EXTERNAL_CSR_MAX_BYTES = 64 * 1024
EXPIRATION_WARNING_DAYS = 30


def _existing_path(v):
    return certificate_storage.resolve_existing(v)


def _safe_name(v):
    return ''.join(
        ch if ch.isalnum() or ch in ('-', '_', '.') else '_'
        for ch in (v or 'certificado')
    )


def _form_flag(name):
    return str(request.form.get(name, '')).lower() in ('1', 'true', 'yes', 'on')


def _read_external_csr_input():
    pasted = (request.form.get('csr_pem') or '').strip()
    uploaded = request.files.get('csr_file')

    if pasted and uploaded and uploaded.filename:
        raise ValueError('Informe a CSR por upload ou colagem, não ambos.')

    if uploaded and uploaded.filename:
        original_filename = secure_filename(uploaded.filename)
        ext = original_filename.rsplit('.', 1)[-1].lower() if '.' in original_filename else ''

        if ext not in EXTERNAL_CSR_FORMATS:
            raise ValueError('Formato de arquivo de CSR não suportado.')

        data = uploaded.read(EXTERNAL_CSR_MAX_BYTES + 1)

        if len(data) > EXTERNAL_CSR_MAX_BYTES:
            raise ValueError('CSR excede o tamanho máximo permitido.')

        if not data:
            raise ValueError('Arquivo de CSR vazio.')

        try:
            return data.decode('utf-8').strip(), original_filename
        except UnicodeDecodeError as exc:
            raise ValueError('CSR deve estar em formato PEM textual.') from exc

    if pasted:
        data = pasted.encode('utf-8')

        if len(data) > EXTERNAL_CSR_MAX_BYTES:
            raise ValueError('CSR excede o tamanho máximo permitido.')

        return pasted, None

    raise ValueError('Informe uma CSR para assinatura.')


def _temp_copy(src, cid, serial, cn, ext):
    src = _existing_path(src)

    if not src:
        return None, None

    fn = f'{_safe_name(cn)}.{ext}'

    dst = os.path.join(
        tempfile.gettempdir(),
        f'certificadora_{cid}_{serial}_{fn}'
    )

    shutil.copyfile(src, dst)

    return dst, fn


def _certificate_name_attr(name, oid):
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _certificate_algorithm(cert):
    key = cert.public_key()
    size = getattr(key, 'key_size', None)
    name = key.__class__.__name__.replace('PublicKey', '')
    return f'{name} {size}' if size else name


def _load_imported_certificate(data, ext, password=None):
    if ext in {'pfx', 'p12'}:
        pwd = password.encode() if password else None
        key, cert, extra_certs = pkcs12.load_key_and_certificates(data, pwd)

        if cert is None and extra_certs:
            cert = extra_certs[0]

        if cert is None:
            raise ValueError('Arquivo PFX/P12 não contém certificado.')

        return cert

    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def _certificate_metadata(cert):
    return {
        'common_name': _certificate_name_attr(cert.subject, NameOID.COMMON_NAME) or cert.subject.rfc4514_string(),
        'issuer': _certificate_name_attr(cert.issuer, NameOID.COMMON_NAME) or cert.issuer.rfc4514_string(),
        'serial': str(cert.serial_number),
        'fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
        'not_before': cert.not_valid_before_utc.replace(tzinfo=None),
        'not_after': cert.not_valid_after_utc.replace(tzinfo=None),
        'algorithm': _certificate_algorithm(cert),
    }


def _days_remaining(cert):
    if not cert.not_after:
        return None

    expires_on = cert.not_after.date() if hasattr(cert.not_after, 'date') else date.fromisoformat(str(cert.not_after)[:10])
    return (expires_on - localnow().date()).days


def _expiration_state(cert):
    if cert.status == 'revoked':
        return {
            'code': 'revoked',
            'label': 'Revogado',
            'severity': 'danger'
        }

    days = _days_remaining(cert)

    if days is None:
        return {
            'code': 'unknown',
            'label': 'Sem validade',
            'severity': 'muted'
        }

    if days < 0:
        return {
            'code': 'expired',
            'label': 'Vencido',
            'severity': 'danger'
        }

    if days <= 7:
        return {
            'code': 'expiring',
            'label': 'Vence em até 7 dias',
            'severity': 'danger'
        }

    if days <= EXPIRATION_WARNING_DAYS:
        return {
            'code': 'expiring',
            'label': 'Vence em até 30 dias',
            'severity': 'warning'
        }

    if days <= 90:
        return {
            'code': 'expiring',
            'label': 'Vence em até 90 dias',
            'severity': 'info'
        }

    return {
        'code': 'valid',
        'label': 'Válido',
        'severity': 'success'
    }


def _get_or_create_certificate_group(db, group_id=None, new_group_name=None, description=''):
    group = None

    if new_group_name:
        name = new_group_name.strip()
        if name:
            group = db.query(CertificateGroup).filter_by(name=name).first()
            if not group:
                group = CertificateGroup(name=name, description=description or '')
                db.add(group)
                db.flush()
                audit_log(
                    'certificate_group_created',
                    'certificates',
                    'info',
                    'Grupo de certificados criado',
                    resource_type='certificate_group',
                    resource_id=str(group.id),
                    resource_name=group.name,
                    result='success'
                )

    if not group and group_id and str(group_id).isdigit():
        group = db.get(CertificateGroup, int(group_id))

    return group


def _monitoring_rows(certificates, groups_by_id):
    rows = []

    for cert in certificates:
        state = _expiration_state(cert)
        rows.append({
            'cert': cert,
            'group': groups_by_id.get(cert.group_id),
            'days_remaining': _days_remaining(cert),
            'expiration': state
        })

    return rows


def _monitoring_status_condition(status_filter, today):
    expiring_until = today + timedelta(days=90)

    if status_filter == 'revoked':
        return Certificate.status == 'revoked'

    if status_filter == 'expired':
        return Certificate.status != 'revoked', Certificate.not_after < today

    if status_filter == 'expiring':
        return (
            Certificate.status != 'revoked',
            Certificate.not_after >= today,
            Certificate.not_after <= expiring_until,
        )

    if status_filter == 'valid':
        return Certificate.status != 'revoked', Certificate.not_after > expiring_until

    return ()


def _apply_monitoring_filters(query, search_filter, group_filter, status_filter, period_filter):
    today = localnow().replace(hour=0, minute=0, second=0, microsecond=0)

    if search_filter:
        needle = f'%{search_filter}%'
        query = query.filter(
            or_(
                Certificate.common_name.like(needle),
                Certificate.serial.like(needle),
                Certificate.fingerprint.like(needle),
                Certificate.issuer.like(needle)
            )
        )

    if group_filter == 'none':
        query = query.filter(Certificate.group_id.is_(None))
    elif group_filter.isdigit():
        query = query.filter(Certificate.group_id == int(group_filter))

    for condition in _monitoring_status_condition(status_filter, today):
        query = query.filter(condition)

    if period_filter == 'expired':
        query = query.filter(Certificate.not_after < today)
    elif period_filter.isdigit():
        until = today + timedelta(days=int(period_filter))
        query = query.filter(Certificate.not_after >= today, Certificate.not_after <= until)

    return query


def _count_monitoring(query):
    return query.order_by(None).count()


def _filter_monitoring_rows_in_memory(rows, search_filter, group_filter, status_filter, period_filter):
    if search_filter:
        needle = search_filter.lower()
        rows = [
            r for r in rows
            if needle in (r['cert'].common_name or '').lower()
            or needle in (r['cert'].serial or '').lower()
            or needle in (r['cert'].fingerprint or '').lower()
            or needle in (r['cert'].issuer or '').lower()
        ]

    if group_filter == 'none':
        rows = [r for r in rows if r['cert'].group_id is None]
    elif group_filter.isdigit():
        rows = [r for r in rows if r['cert'].group_id == int(group_filter)]

    if status_filter:
        rows = [r for r in rows if r['expiration']['code'] == status_filter]

    if period_filter:
        if period_filter == 'expired':
            rows = [r for r in rows if r['days_remaining'] is not None and r['days_remaining'] < 0]
        elif period_filter.isdigit():
            days = int(period_filter)
            rows = [
                r for r in rows
                if r['days_remaining'] is not None and 0 <= r['days_remaining'] <= days
            ]

    return rows


@bp.route('/request/new', methods=['GET', 'POST'])
@login_required
@permission_required('cert.request')
def new_request():
    if request.method == 'POST':
        db = AppSession()

        san = {
            k: request.form.get(f'san_{k}', '').split()
            for k in ['dns', 'ip', 'email', 'uri']
        }

        try:
            requested_days = int(request.form.get('validity_days', '365'))
        except ValueError:
            requested_days = 365

        days = min(requested_days, Config.MAX_CERT_VALIDITY_DAYS)

        try:
            rsa_key_size = int(request.form.get('rsa_key_size', '2048'))
        except ValueError:
            rsa_key_size = 2048

        r = CertificateRequest(
            requester_id=current_user.id,
            status='pending',
            cert_type=request.form.get('cert_type'),
            common_name=request.form.get('common_name'),
            organization=request.form.get('organization') or DEFAULT_SUBJECT['organization'],
            org_unit=request.form.get('org_unit') or DEFAULT_SUBJECT['org_unit'],
            country=request.form.get('country') or DEFAULT_SUBJECT['country'],
            state=request.form.get('state') or DEFAULT_SUBJECT['state'],
            locality=request.form.get('locality') or DEFAULT_SUBJECT['locality'],
            email=request.form.get('email') or DEFAULT_SUBJECT['email'],
            validity_days=days,
            key_algorithm=request.form.get('key_algorithm', 'RSA'),
            rsa_key_size=rsa_key_size,
            san_json=san,
            justification=request.form.get('justification'),
            environment=request.form.get('environment'),
            technical_owner=request.form.get('technical_owner'),
            area=request.form.get('area'),
            notes=request.form.get('notes'),
            generated_by_system=True
        )

        db.add(r)
        db.commit()

        audit_log(
            'certificate_request_created',
            'requests',
            'info',
            'Solicitação criada',
            request_id=r.id,
            resource_name=r.common_name,
            status_after='pending',
            result='success'
        )

        return redirect(url_for('certs.list_requests'))

    return render_template('certs/new_request.html', defaults=DEFAULT_SUBJECT)


@bp.route('/request/external-csr', methods=['GET', 'POST'])
@login_required
@permission_required('cert.request')
def external_csr_request():
    if request.method == 'POST':
        db = AppSession()

        try:
            csr_pem, original_filename = _read_external_csr_input()
            csr_meta = extract_external_csr_metadata(csr_pem)
        except (ValueError, CertificateSigningRequestInvalid) as exc:
            audit_log(
                'external_csr_request_invalid',
                'requests',
                'warning',
                'CSR externa rejeitada na submissão',
                result='failure',
                reason=str(exc)[:500]
            )
            flash(str(exc))
            return redirect(url_for('certs.external_csr_request'))

        try:
            requested_days = int(request.form.get('validity_days', '365'))
        except ValueError:
            requested_days = 365

        days = min(max(requested_days, 1), Config.MAX_CERT_VALIDITY_DAYS)

        r = CertificateRequest(
            requester_id=current_user.id,
            status='pending',
            cert_type=request.form.get('cert_type') or 'CSR Externa',
            common_name=csr_meta['common_name'],
            organization=csr_meta['organization'] or DEFAULT_SUBJECT['organization'],
            org_unit=csr_meta['org_unit'] or DEFAULT_SUBJECT['org_unit'],
            country=csr_meta['country'] or DEFAULT_SUBJECT['country'],
            state=csr_meta['state'] or DEFAULT_SUBJECT['state'],
            locality=csr_meta['locality'] or DEFAULT_SUBJECT['locality'],
            email=csr_meta['email'] or request.form.get('email') or DEFAULT_SUBJECT['email'],
            validity_days=days,
            key_algorithm=csr_meta['key_algorithm'],
            rsa_key_size=csr_meta['rsa_key_size'],
            ecdsa_curve=csr_meta['ecdsa_curve'],
            san_json=csr_meta['san_json'],
            justification=request.form.get('justification'),
            environment=request.form.get('environment'),
            technical_owner=request.form.get('technical_owner'),
            area=request.form.get('area'),
            notes=request.form.get('notes'),
            csr_pem=csr_pem,
            generated_by_system=False
        )

        db.add(r)
        db.commit()

        audit_log(
            'external_csr_request_created',
            'requests',
            'info',
            'Solicitação de assinatura de CSR externa criada',
            request_id=r.id,
            resource_name=r.common_name,
            status_after='pending',
            result='success',
            details={
                'filename': original_filename,
                'algorithm': r.key_algorithm
            }
        )

        flash('CSR externa recebida e enviada para aprovação.')
        return redirect(url_for('certs.list_requests'))

    return render_template('certs/external_csr_request.html', defaults=DEFAULT_SUBJECT)


@bp.route('/requests')
@login_required
@permission_required('cert.view')
def list_requests():
    db = AppSession()

    rows = (
        db.query(CertificateRequest)
        .options(
            joinedload(CertificateRequest.requester),
            joinedload(CertificateRequest.approver)
        )
        .order_by(CertificateRequest.id.desc())
        .limit(200)
        .all()
    )

    return render_template('certs/requests.html', rows=rows)


@bp.route('/requests/<int:rid>/approve', methods=['POST'])
@login_required
@permission_required('cert.approve')
def approve(rid):
    db = AppSession()
    r = db.get(CertificateRequest, rid)

    if not r:
        abort(404)

    if r.status != 'pending':
        flash('Esta solicitação já foi decidida.')
        return redirect(url_for('certs.list_requests'))

    before = r.status

    r.status = 'approved'
    r.approval_comment = request.form.get('comment')
    r.approver_id = current_user.id
    r.decided_at = localnow()

    try:
        if r.generated_by_system is False and r.csr_pem:
            meta = issue_external_csr(r, rid)
        else:
            meta = issue_certificate(r, rid)
    except CertificateAuthorityUnavailable:
        db.rollback()
        audit_log(
            'certificate_request_approval_failed',
            'requests',
            'error',
            'Aprovação bloqueada por indisponibilidade da CA',
            request_id=rid,
            status_before=before,
            result='failure',
            reason='ca_unavailable'
        )
        flash('Não foi possível aprovar a solicitação: arquivos da CA indisponíveis ou inválidos. Acione o administrador da plataforma.')
        return redirect(url_for('certs.list_requests'))
    except CertificateSigningRequestInvalid as exc:
        db.rollback()
        audit_log(
            'external_csr_approval_failed',
            'requests',
            'warning',
            'Aprovação bloqueada por CSR externa inválida',
            request_id=rid,
            status_before=before,
            result='failure',
            reason=str(exc)[:500]
        )
        flash('Não foi possível aprovar a CSR externa: valide o conteúdo da CSR e submeta novamente.')
        return redirect(url_for('certs.list_requests'))

    c = Certificate(
        request_id=r.id,
        serial=meta['serial'],
        fingerprint=meta['fingerprint'],
        common_name=r.common_name,
        issuer=meta.get('issuer'),
        cert_path=meta['cert_path'],
        key_path=meta['key_path'],
        csr_path=meta['csr_path'],
        not_before=meta['not_before'],
        not_after=meta['not_after'],
        algorithm=meta.get('algorithm') or r.key_algorithm,
        source='external_csr' if r.generated_by_system is False else 'issued',
        source_format='csr' if r.generated_by_system is False else None
    )

    db.add(c)
    db.commit()

    audit_log(
        'certificate_request_approved',
        'requests',
        'info',
        'Solicitação aprovada',
        request_id=rid,
        certificate_id=c.id,
        status_before=before,
        status_after='approved',
        result='success'
    )

    return redirect(url_for('certs.list_requests'))


@bp.route('/requests/<int:rid>/reject', methods=['POST'])
@login_required
@permission_required('cert.approve')
def reject(rid):
    db = AppSession()
    r = db.get(CertificateRequest, rid)

    if not r:
        abort(404)

    if r.status != 'pending':
        flash('Esta solicitação já foi decidida.')
        return redirect(url_for('certs.list_requests'))

    before = r.status

    r.status = 'rejected'
    r.rejection_reason = request.form.get('reason')
    r.approver_id = current_user.id
    r.decided_at = localnow()

    db.commit()

    audit_log(
        'certificate_request_rejected',
        'requests',
        'info',
        'Solicitação reprovada',
        request_id=rid,
        status_before=before,
        status_after='rejected',
        reason=r.rejection_reason,
        result='success'
    )

    return redirect(url_for('certs.list_requests'))


@bp.route('/issued')
@login_required
@permission_required('cert.view')
def issued():
    db = AppSession()

    rows = (
        db.query(Certificate)
        .order_by(Certificate.id.desc())
        .limit(200)
        .all()
    )

    return render_template(
        'certs/issued.html',
        rows=rows,
        allow_unprotected_pkcs12_export=Config.ALLOW_UNPROTECTED_PKCS12_EXPORT
    )


@bp.route('/monitoring')
@login_required
@permission_required('cert.view')
def monitoring():
    db = AppSession()

    search_filter = (request.args.get('q') or '').strip()
    group_filter = (request.args.get('group_id') or '').strip()
    status_filter = (request.args.get('status') or '').strip()
    period_filter = (request.args.get('period') or '').strip()
    try:
        page = max(1, int(request.args.get('page', '1')))
    except ValueError:
        page = 1
    per_page = 25

    groups = db.query(CertificateGroup).order_by(CertificateGroup.name.asc()).all()
    groups_by_id = {g.id: g for g in groups}

    group_counts = {g.id: 0 for g in groups}
    ungrouped_count = 0
    try:
        group_count_rows = (
            db.query(Certificate.group_id, func.count(Certificate.id))
            .group_by(Certificate.group_id)
            .all()
        )
    except TypeError:
        fallback_counts = {}
        for cert in db.query(Certificate).all():
            fallback_counts[cert.group_id] = fallback_counts.get(cert.group_id, 0) + 1
        group_count_rows = fallback_counts.items()
    for group_id, total in group_count_rows:
        if group_id in group_counts:
            group_counts[group_id] = total
        elif group_id is None:
            ungrouped_count = total

    base_query = db.query(Certificate)
    filtered_query = _apply_monitoring_filters(
        base_query,
        search_filter,
        group_filter,
        status_filter,
        period_filter
    )

    if not hasattr(filtered_query, 'offset'):
        certificates = (
            filtered_query
            .order_by(Certificate.not_after.asc(), Certificate.common_name.asc())
            .all()
        )
        rows = _filter_monitoring_rows_in_memory(
            _monitoring_rows(certificates, groups_by_id),
            search_filter,
            group_filter,
            status_filter,
            period_filter
        )
        summary = {
            'total': len(rows),
            'expired': len([r for r in rows if r['expiration']['code'] == 'expired']),
            'expiring_7': len([r for r in rows if r['days_remaining'] is not None and 0 <= r['days_remaining'] <= 7]),
            'expiring_30': len([r for r in rows if r['days_remaining'] is not None and 0 <= r['days_remaining'] <= 30]),
            'valid': len([r for r in rows if r['expiration']['code'] == 'valid']),
        }
        total_rows = len(rows)
        total_pages = max(1, (total_rows + per_page - 1) // per_page)
        page = min(page, total_pages)
        page_start = (page - 1) * per_page
        rows = rows[page_start:page_start + per_page]

        return render_template(
            'certs/monitoring.html',
            rows=rows,
            groups=groups,
            group_counts=group_counts,
            ungrouped_count=ungrouped_count,
            filters={
                'q': search_filter,
                'group_id': group_filter,
                'status': status_filter,
                'period': period_filter,
            },
            pagination={
                'page': page,
                'per_page': per_page,
                'total': total_rows,
                'total_pages': total_pages,
                'has_prev': page > 1,
                'has_next': page < total_pages,
                'prev_page': page - 1,
                'next_page': page + 1,
            },
            summary=summary,
            accepted_formats=', '.join(f'.{fmt}' for fmt in sorted(IMPORT_CERTIFICATE_FORMATS))
        )

    today = localnow().replace(hour=0, minute=0, second=0, microsecond=0)
    expiring_7 = today + timedelta(days=7)
    expiring_30 = today + timedelta(days=30)
    expiring_90 = today + timedelta(days=90)
    total_rows = _count_monitoring(filtered_query)

    summary = {
        'total': total_rows,
        'expired': _count_monitoring(filtered_query.filter(Certificate.status != 'revoked', Certificate.not_after < today)),
        'expiring_7': _count_monitoring(filtered_query.filter(Certificate.status != 'revoked', Certificate.not_after >= today, Certificate.not_after <= expiring_7)),
        'expiring_30': _count_monitoring(filtered_query.filter(Certificate.status != 'revoked', Certificate.not_after >= today, Certificate.not_after <= expiring_30)),
        'valid': _count_monitoring(filtered_query.filter(Certificate.status != 'revoked', Certificate.not_after > expiring_90)),
    }

    total_pages = max(1, (total_rows + per_page - 1) // per_page)
    page = min(page, total_pages)
    page_start = (page - 1) * per_page
    page_query = filtered_query.order_by(Certificate.not_after.asc(), Certificate.common_name.asc())
    if hasattr(page_query, 'offset'):
        certificates = page_query.offset(page_start).limit(per_page).all()
    else:
        certificates = page_query.all()[page_start:page_start + per_page]
    rows = _monitoring_rows(certificates, groups_by_id)

    return render_template(
        'certs/monitoring.html',
        rows=rows,
        groups=groups,
        group_counts=group_counts,
        ungrouped_count=ungrouped_count,
        filters={
            'q': search_filter,
            'group_id': group_filter,
            'status': status_filter,
            'period': period_filter,
        },
        pagination={
            'page': page,
            'per_page': per_page,
            'total': total_rows,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_page': page - 1,
            'next_page': page + 1,
        },
        summary=summary,
        accepted_formats=', '.join(f'.{fmt}' for fmt in sorted(IMPORT_CERTIFICATE_FORMATS))
    )


@bp.route('/groups/create', methods=['POST'])
@login_required
@permission_required('cert.request')
def create_certificate_group():
    db = AppSession()
    name = (request.form.get('name') or '').strip()
    description = (request.form.get('description') or '').strip()

    if not name:
        flash('Informe o nome do grupo de certificados.')
        return redirect(url_for('certs.monitoring'))

    if db.query(CertificateGroup).filter_by(name=name).first():
        flash('Já existe um grupo de certificados com esse nome.')
        return redirect(url_for('certs.monitoring'))

    group = CertificateGroup(name=name, description=description)
    db.add(group)
    db.commit()

    audit_log(
        'certificate_group_created',
        'certificates',
        'info',
        'Grupo de certificados criado',
        resource_type='certificate_group',
        resource_id=str(group.id),
        resource_name=group.name,
        result='success'
    )

    flash('Grupo de certificados criado com sucesso.')
    return redirect(url_for('certs.monitoring'))


@bp.route('/groups/<int:gid>/update', methods=['POST'])
@login_required
@permission_required('cert.request')
def update_certificate_group(gid):
    db = AppSession()
    group = db.get(CertificateGroup, gid)

    if not group:
        flash('Grupo de certificados não encontrado.')
        return redirect(url_for('certs.monitoring'))

    name = (request.form.get('name') or '').strip()
    description = (request.form.get('description') or '').strip()

    if not name:
        flash('Informe o nome do grupo de certificados.')
        return redirect(url_for('certs.monitoring'))

    if db.query(CertificateGroup).filter(CertificateGroup.name == name, CertificateGroup.id != gid).first():
        flash('Já existe outro grupo de certificados com esse nome.')
        return redirect(url_for('certs.monitoring'))

    old_name = group.name
    group.name = name
    group.description = description
    db.commit()

    audit_log(
        'certificate_group_updated',
        'certificates',
        'info',
        'Grupo de certificados atualizado',
        resource_type='certificate_group',
        resource_id=str(group.id),
        resource_name=group.name,
        result='success',
        details={
            'old_name': old_name
        }
    )

    flash('Grupo de certificados atualizado com sucesso.')
    return redirect(url_for('certs.monitoring'))


@bp.route('/groups/<int:gid>/delete', methods=['POST'])
@login_required
@permission_required('cert.request')
def delete_certificate_group(gid):
    db = AppSession()
    group = db.get(CertificateGroup, gid)

    if not group:
        flash('Grupo de certificados não encontrado.')
        return redirect(url_for('certs.monitoring'))

    group_name = group.name
    affected = db.query(Certificate).filter(Certificate.group_id == gid).count()
    db.query(Certificate).filter(Certificate.group_id == gid).update({'group_id': None})
    db.delete(group)
    db.commit()

    audit_log(
        'certificate_group_deleted',
        'certificates',
        'warning',
        'Grupo de certificados excluído',
        resource_type='certificate_group',
        resource_id=str(gid),
        resource_name=group_name,
        result='success',
        details={
            'disassociated_certificates': affected
        }
    )

    flash('Grupo excluído. Certificados associados ficaram sem grupo.')
    return redirect(url_for('certs.monitoring'))


@bp.route('/<int:cid>/group', methods=['POST'])
@login_required
@permission_required('cert.request')
def update_certificate_group_assignment(cid):
    db = AppSession()
    cert = db.get(Certificate, cid)

    if not cert:
        abort(404)

    old_group_id = cert.group_id
    group_id = (request.form.get('group_id') or '').strip()
    group = _get_or_create_certificate_group(
        db,
        group_id=group_id,
        new_group_name=request.form.get('new_group_name'),
        description=request.form.get('new_group_description') or ''
    )

    cert.group_id = group.id if group else None
    db.commit()

    audit_log(
        'certificate_group_assignment_updated',
        'certificates',
        'info',
        'Associação de certificado a grupo atualizada',
        certificate_id=cid,
        certificate_serial=cert.serial,
        result='success',
        details={
            'old_group_id': old_group_id,
            'new_group_id': cert.group_id
        }
    )

    flash('Grupo do certificado atualizado.')
    return redirect(url_for('certs.monitoring'))


@bp.route('/import', methods=['POST'])
@login_required
@permission_required('cert.request')
def import_certificate():
    db = AppSession()
    uploaded = request.files.get('certificate_file')

    if not uploaded or not uploaded.filename:
        flash('Selecione um arquivo de certificado para importar.')
        return redirect(url_for('certs.monitoring'))

    original_filename = secure_filename(uploaded.filename)
    ext = original_filename.rsplit('.', 1)[-1].lower() if '.' in original_filename else ''

    if ext not in IMPORT_CERTIFICATE_FORMATS:
        flash('Formato de certificado não suportado para importação.')
        return redirect(url_for('certs.monitoring'))

    data = uploaded.read()

    if not data:
        flash('Arquivo vazio ou inválido.')
        return redirect(url_for('certs.monitoring'))

    try:
        parsed_cert = _load_imported_certificate(
            data,
            ext,
            password=request.form.get('pfx_password') or None
        )
    except ValueError as exc:
        audit_log(
            'certificate_import_failed',
            'certificates',
            'warning',
            'Falha ao importar certificado',
            result='failure',
            reason=str(exc)[:500],
            details={
                'filename': original_filename,
                'format': ext
            }
        )
        flash('Não foi possível ler o certificado. Verifique o formato e a senha, se for PFX/P12 protegido.')
        return redirect(url_for('certs.monitoring'))

    meta = _certificate_metadata(parsed_cert)
    group = _get_or_create_certificate_group(
        db,
        group_id=request.form.get('group_id'),
        new_group_name=request.form.get('new_group_name'),
        description=request.form.get('new_group_description') or ''
    )

    existing = db.query(Certificate).filter_by(fingerprint=meta['fingerprint']).first()

    if existing:
        old_group_id = existing.group_id
        existing.group_id = group.id if group else existing.group_id
        existing.issuer = existing.issuer or meta['issuer']
        existing.source_format = existing.source_format or ext
        db.commit()

        audit_log(
            'certificate_import_duplicate',
            'certificates',
            'info',
            'Certificado importado já existia',
            certificate_id=existing.id,
            certificate_serial=existing.serial,
            result='duplicate',
            details={
                'filename': original_filename,
                'format': ext,
                'old_group_id': old_group_id,
                'new_group_id': existing.group_id
            }
        )

        flash('Certificado já existia no sistema. A associação de grupo foi atualizada quando informada.')
        return redirect(url_for('certs.monitoring'))

    cert_path = certificate_storage.imported_certificate_path(meta['fingerprint'])
    certificate_storage.write_bytes(
        cert_path,
        parsed_cert.public_bytes(serialization.Encoding.PEM)
    )

    cert = Certificate(
        group_id=group.id if group else None,
        serial=meta['serial'],
        fingerprint=meta['fingerprint'],
        common_name=meta['common_name'],
        issuer=meta['issuer'],
        status='issued',
        not_before=meta['not_before'],
        not_after=meta['not_after'],
        cert_path=cert_path,
        key_path=None,
        csr_path=None,
        algorithm=meta['algorithm'],
        source='imported',
        source_format=ext,
        original_filename=original_filename,
        imported_at=localnow()
    )

    db.add(cert)
    db.commit()

    audit_log(
        'certificate_import_success',
        'certificates',
        'info',
        'Certificado importado para monitoramento',
        certificate_id=cert.id,
        certificate_serial=cert.serial,
        certificate_fingerprint=cert.fingerprint,
        result='success',
        details={
            'filename': original_filename,
            'format': ext,
            'group_id': cert.group_id,
            'days_remaining': _days_remaining(cert)
        }
    )

    flash('Certificado importado para monitoramento com sucesso.')
    return redirect(url_for('certs.monitoring'))


@bp.route('/<int:cid>/revoke', methods=['POST'])
@login_required
@permission_required('cert.revoke')
def revoke(cid):
    db = AppSession()
    c = db.get(Certificate, cid)

    if not c:
        abort(404)

    if c.status == 'revoked':
        flash('Este certificado já está revogado.')
        return redirect(url_for('certs.issued'))

    reason = (request.form.get('reason') or 'unspecified').strip()
    comment = (request.form.get('comment') or '').strip()
    revoked_at = localnow()

    c.status = 'revoked'
    c.revoked_at = revoked_at
    c.revocation_reason = reason
    c.revocation_comment = comment

    db.add(
        Revocation(
            certificate_id=cid,
            revoked_by=current_user.id,
            reason=reason,
            comment=comment,
            revoked_at=revoked_at
        )
    )

    db.commit()

    audit_log(
        'certificate_revoked',
        'certificates',
        'critical',
        'Certificado revogado',
        certificate_id=cid,
        certificate_serial=c.serial,
        result='success',
        reason=reason,
        details={
            'comment': comment
        }
    )

    flash('Certificado revogado com sucesso.')

    return redirect(url_for('certs.issued'))


def _load_private_key(c):
    key_path = _existing_path(c.key_path)

    if not key_path:
        abort(404)

    with open(key_path, 'rb') as f:
        data = f.read()

    try:
        return serialization.load_pem_private_key(
            data,
            password=Config.SECRET_KEY.encode()[:32] or b'change-me'
        )
    except TypeError:
        return serialization.load_pem_private_key(
            data,
            password=None
        )


@bp.route('/<int:cid>/download/<fmt>', methods=['GET', 'POST'])
@login_required
@permission_required('cert.download')
def download(cid, fmt):
    fmt = fmt.lower()

    db = AppSession()
    c = db.get(Certificate, cid)

    if not c:
        abort(404)

    if c.status == 'revoked' and fmt in REVOKED_BLOCKED_DOWNLOAD_FORMATS:
        flash('Download indisponível: certificado revogado.')
        return redirect(url_for('certs.issued'))

    path = None
    filename = None
    pkcs12_unprotected_export = False

    if fmt in ['crt', 'cer', 'pem']:
        path, filename = _temp_copy(
            c.cert_path,
            cid,
            c.serial,
            c.common_name,
            fmt
        )

    elif fmt == 'csr':
        path, filename = _temp_copy(
            c.csr_path,
            cid,
            c.serial,
            c.common_name,
            'csr'
        )

    elif fmt == 'key':
        path, filename = _temp_copy(
            c.key_path,
            cid,
            c.serial,
            c.common_name,
            'key'
        )

    elif fmt == 'der':
        cert_path = _existing_path(c.cert_path)

        if not cert_path:
            abort(404)

        with open(cert_path, 'rb') as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data)

        filename = f'{_safe_name(c.common_name)}.der'

        path = os.path.join(
            tempfile.gettempdir(),
            f'certificadora_{cid}_{c.serial}_{filename}'
        )

        with open(path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

    elif fmt in ['pfx', 'p12']:
        pwd = request.form.get('pfx_password') or request.args.get('pfx_password')
        export_unprotected = _form_flag('export_unprotected')
        pkcs12_unprotected_export = export_unprotected

        if export_unprotected and not Config.ALLOW_UNPROTECTED_PKCS12_EXPORT:
            audit_log(
                'certificate_unprotected_pkcs12_export_denied',
                'certificates',
                'warning',
                'Exportação PFX/P12 sem senha bloqueada pela configuração',
                certificate_id=cid,
                certificate_serial=c.serial,
                result='denied',
                details={
                    'format': fmt
                }
            )

            flash('Exportação PFX/P12 sem senha está desabilitada neste ambiente.')
            return redirect(url_for('certs.issued'))

        if export_unprotected:
            encryption_algorithm = serialization.NoEncryption()
        elif not pwd:
            flash('Informe uma senha para gerar o PFX/P12.')
            return redirect(url_for('certs.issued'))
        else:
            encryption_algorithm = serialization.BestAvailableEncryption(
                pwd.encode()
            )

        cert_path = _existing_path(c.cert_path)

        if not cert_path:
            abort(404)

        with open(cert_path, 'rb') as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data)
        key = _load_private_key(c)

        data = pkcs12.serialize_key_and_certificates(
            name=(c.common_name or f'cert-{cid}').encode(),
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=encryption_algorithm
        )

        filename = f'{_safe_name(c.common_name)}.{fmt}'

        path = os.path.join(
            tempfile.gettempdir(),
            f'certificadora_{cid}_{c.serial}_{filename}'
        )

        with open(path, 'wb') as f:
            f.write(data)

    elif fmt == 'zip':
        filename = f'{_safe_name(c.common_name)}.zip'

        path = os.path.join(
            tempfile.gettempdir(),
            f'certificadora_{cid}_{c.serial}_{filename}'
        )

        with zipfile.ZipFile(path, 'w') as z:
            files_to_zip = [
                (c.cert_path, 'crt'),
                (c.csr_path, 'csr'),
                (c.key_path, 'key')
            ]

            for src, ext in files_to_zip:
                real = _existing_path(src)

                if real:
                    z.write(
                        real,
                        f'{_safe_name(c.common_name)}.{ext}'
                    )

    else:
        abort(400)

    if not path or not os.path.exists(path):
        abort(404)

    audit_details = {
        'format': fmt
    }

    if fmt in ['pfx', 'p12']:
        audit_details['pkcs12_encrypted'] = not pkcs12_unprotected_export

    audit_log(
        'certificate_download_success',
        'certificates',
        'warning' if pkcs12_unprotected_export else 'info',
        'Download PFX/P12 sem senha concluído' if pkcs12_unprotected_export else 'Download concluído',
        certificate_id=cid,
        certificate_serial=c.serial,
        result='success',
        details=audit_details
    )

    return send_file(
        path,
        as_attachment=True,
        download_name=filename,
        mimetype=MIME_TYPES.get(fmt, 'application/octet-stream')
    )
