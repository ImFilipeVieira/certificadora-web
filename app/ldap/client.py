from ldap3 import Server, Connection, ALL, SUBTREE
from app.config import Config
from app.audit.logger import audit_log


def _authenticate_mock(username, password):
    if not Config.MOCK_AUTH_PASSWORD or password != Config.MOCK_AUTH_PASSWORD:
        audit_log('mock_login_failure', 'authentication', 'warning', 'Falha no login mock', actor_username=username, result='failure')
        return None

    audit_log('mock_login_success', 'authentication', 'info', 'Login mock validado', actor_username=username, result='success')
    safe_username = username or 'demo.user'
    return {
        'username': safe_username,
        'display_name': 'Usuario Demo',
        'email': f'{safe_username}@example.com',
    }


def authenticate_ad(username,password):
    if not password: return None
    if Config.AUTH_PROVIDER == 'mock':
        return _authenticate_mock(username, password)
    try:
        server=Server(Config.LDAP_HOST, port=Config.LDAP_PORT, use_ssl=Config.LDAP_USE_SSL, get_info=ALL)
        svc=Connection(server, user=Config.LDAP_BIND_DN, password=Config.LDAP_BIND_PASSWORD, auto_bind=True)
        audit_log('ldap_bind_success','authentication','info','Bind de serviço LDAP realizado', actor_username=username, ldap_auth_result='service_bind_success')
        svc.search(Config.LDAP_BASE_DN, f'({Config.LDAP_SEARCH_ATTRIBUTE}={username})', SUBTREE, attributes=['distinguishedName','displayName','mail'])
        if not svc.entries: audit_log('ldap_user_not_found','authentication','warning','Usuário não encontrado', actor_username=username); return None
        e=svc.entries[0]; dn=str(e.distinguishedName); Connection(server, user=dn, password=password, auto_bind=True)
        audit_log('login_password_success','authentication','info','Senha validada no AD', actor_username=username, ldap_auth_result='success')
        return {'username':username,'display_name':str(e.displayName or username),'email':str(e.mail or '')}
    except Exception as exc:
        audit_log('ldap_bind_failure','authentication','warning','Falha LDAP', actor_username=username, ldap_auth_result='failure', reason=str(exc)[:500]); return None
