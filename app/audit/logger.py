import uuid
from datetime import datetime, timezone
from flask import request, session, has_request_context
from flask_login import current_user
from app import AuditSession
from app.models import AuditLog
def audit_log(event_type, category, severity, message, **kw):
    db=AuditSession(); now=datetime.now(timezone.utc).replace(tzinfo=None); au=kw.get('actor_username'); aid=kw.get('actor_user_id'); adn=kw.get('actor_display_name')
    if has_request_context() and getattr(current_user,'is_authenticated',False): aid=current_user.id; au=current_user.username; adn=current_user.display_name
    rec=AuditLog(event_id=str(uuid.uuid4()), timestamp_utc=now, timestamp_local=datetime.utcnow().replace(tzinfo=None), event_type=event_type, event_category=category, severity=severity, message=message, actor_user_id=aid, actor_username=au, actor_display_name=adn, actor_groups=kw.get('actor_groups'), action=kw.get('action',event_type), resource_type=kw.get('resource_type'), resource_id=kw.get('resource_id'), resource_name=kw.get('resource_name'), request_id=kw.get('request_id'), certificate_id=kw.get('certificate_id'), certificate_serial=kw.get('certificate_serial'), certificate_fingerprint=kw.get('certificate_fingerprint'), status_before=kw.get('status_before'), status_after=kw.get('status_after'), result=kw.get('result'), reason=kw.get('reason'), details_json=kw.get('details',{}), ip_address=request.remote_addr if has_request_context() else None, forwarded_for=request.headers.get('X-Forwarded-For') if has_request_context() else None, user_agent=request.headers.get('User-Agent') if has_request_context() else None, session_id=session.get('_id') if has_request_context() else None, mfa_status=kw.get('mfa_status'), ldap_auth_result=kw.get('ldap_auth_result'), http_method=request.method if has_request_context() else None, endpoint=request.path if has_request_context() else None, http_status_code=kw.get('http_status_code'))
    db.add(rec); db.commit(); return rec.event_id
