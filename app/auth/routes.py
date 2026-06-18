import io, base64, pyotp, qrcode
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required
from app import AppSession, login_manager
from app.models import User, Group, Permission, UserGroup, GroupPermission
from app.ldap.client import authenticate_ad
from app.audit.logger import audit_log
from app.config import Config
from app.permissions.decorators import has_any_permission

bp = Blueprint('auth', __name__)
MAX_ATTEMPTS = 5
LOCK_TIME_MINUTES = 15
DEMO_PERMISSION_CODES = (
    'cert.request',
    'cert.view',
    'cert.approve',
    'cert.download',
    'cert.revoke',
    'users.manage',
    'groups.manage',
    'mfa.reset',
    'audit.view',
    'audit.export',
)


@login_manager.user_loader
def load_user(uid):
    return AppSession().get(User, int(uid))


def _post_login_redirect(user):
    if not has_any_permission(user.id):
        audit_log('user_logged_in_without_permissions', 'authorization', 'warning', 'Usuário logado sem permissões/grupos internos', actor_user_id=user.id, actor_username=user.username, result='no_permissions')
        return redirect(url_for('dashboard.no_access'))
    return redirect(url_for('dashboard.index'))


def _grant_demo_permissions(db, user):
    if not Config.DEMO_MODE:
        return

    group = db.query(Group).filter_by(name='Demo Admin').first()
    if not group:
        group = Group(name='Demo Admin', description='Grupo administrativo ficticio para portfolio local.')
        db.add(group)
        db.flush()

    for code in DEMO_PERMISSION_CODES:
        permission = db.query(Permission).filter_by(code=code).first()
        if not permission:
            permission = Permission(code=code, description=f'Permissao demo: {code}')
            db.add(permission)
            db.flush()

        if not db.query(GroupPermission).filter_by(group_id=group.id, permission_id=permission.id).first():
            db.add(GroupPermission(group_id=group.id, permission_id=permission.id))

    if not db.query(UserGroup).filter_by(user_id=user.id, group_id=group.id).first():
        db.add(UserGroup(user_id=user.id, group_id=group.id))

    db.commit()


@bp.route('/login', methods=['GET', 'POST'])
def login():
    db = AppSession()
    if request.method == 'GET':
        audit_log('login_page_opened', 'authentication', 'info', 'Tela de login aberta')
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        audit_log('login_attempt', 'authentication', 'info', 'Tentativa de login', actor_username=username)
        local_user = db.query(User).filter_by(username=username).first()
        now = datetime.utcnow()

        if local_user and local_user.locked_until and local_user.locked_until > now:
            audit_log('login_blocked', 'security', 'critical', 'Login bloqueado por proteção contra força bruta', actor_user_id=local_user.id, actor_username=username, result='blocked', details={'locked_until': local_user.locked_until.isoformat(), 'failed_login_attempts': local_user.failed_login_attempts})
            flash('Usuário bloqueado temporariamente por muitas tentativas inválidas. Procure um administrador ou aguarde o desbloqueio automático.')
            return render_template('auth/login.html')

        info = authenticate_ad(username, password)
        if not info:
            if local_user:
                local_user.failed_login_attempts = (local_user.failed_login_attempts or 0) + 1
                if local_user.failed_login_attempts >= MAX_ATTEMPTS:
                    local_user.locked_until = now + timedelta(minutes=LOCK_TIME_MINUTES)
                    audit_log('user_locked', 'security', 'critical', 'Usuário bloqueado por tentativas inválidas de login', actor_user_id=local_user.id, actor_username=username, result='locked', details={'failed_login_attempts': local_user.failed_login_attempts, 'locked_until': local_user.locked_until.isoformat(), 'lock_time_minutes': LOCK_TIME_MINUTES})
                db.commit()
            audit_log('login_password_failure', 'authentication', 'warning', 'Login inválido', actor_username=username, result='failure')
            flash('Usuário ou senha inválidos')
            return render_template('auth/login.html')

        user = db.query(User).filter_by(username=username).first()
        if not user:
            user = User(username=username, display_name=info['display_name'], email=info['email'], failed_login_attempts=0, locked_until=None)
            db.add(user)
            db.commit()
            audit_log('local_user_created_no_permissions', 'authentication', 'info', 'Usuário local criado sem grupos/permissões por padrão', actor_user_id=user.id, actor_username=username, result='created_without_permissions')
        else:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.commit()
            audit_log('login_password_success', 'authentication', 'info', 'Senha validada e contador de falhas zerado', actor_user_id=user.id, actor_username=username, ldap_auth_result='success')

        _grant_demo_permissions(db, user)
        if not Config.MFA_REQUIRED:
            login_user(user)
            audit_log('session_created_without_mfa', 'authentication', 'warning', 'Sessao demo criada sem MFA', actor_username=user.username)
            return _post_login_redirect(user)

        session['pre_mfa_user_id'] = user.id
        return redirect(url_for('auth.mfa_setup' if not user.mfa_enabled else 'auth.mfa_verify'))
    return render_template('auth/login.html')


@bp.route('/mfa/setup', methods=['GET', 'POST'])
def mfa_setup():
    db = AppSession()
    user = db.get(User, session.get('pre_mfa_user_id'))
    if not user:
        return redirect(url_for('auth.login'))
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        db.commit()
        audit_log('mfa_setup_started', 'authentication', 'info', 'Cadastro MFA iniciado', actor_username=user.username)
    if request.method == 'POST':
        audit_log('mfa_validation_started', 'authentication', 'info', 'Validação MFA iniciada no cadastro', actor_username=user.username)
        if pyotp.TOTP(user.mfa_secret).verify(request.form.get('code', ''), valid_window=1):
            user.mfa_enabled = True
            db.commit()
            login_user(user)
            session.pop('pre_mfa_user_id', None)
            audit_log('mfa_setup_completed', 'authentication', 'info', 'MFA cadastrado', actor_username=user.username, mfa_status='success')
            audit_log('session_created', 'authentication', 'info', 'Sessão criada', actor_username=user.username)
            return _post_login_redirect(user)
        audit_log('mfa_validation_failure', 'authentication', 'warning', 'Falha MFA no cadastro', actor_username=user.username, mfa_status='failure')
    uri = pyotp.TOTP(user.mfa_secret).provisioning_uri(user.username, issuer_name=Config.MFA_ISSUER)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return render_template('auth/mfa_setup.html', qr=base64.b64encode(buf.getvalue()).decode())


@bp.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    db = AppSession()
    user = db.get(User, session.get('pre_mfa_user_id'))
    if not user:
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        audit_log('mfa_validation_started', 'authentication', 'info', 'Validação MFA iniciada', actor_username=user.username)
        if pyotp.TOTP(user.mfa_secret).verify(request.form.get('code', ''), valid_window=1):
            login_user(user)
            session.pop('pre_mfa_user_id', None)
            audit_log('mfa_validation_success', 'authentication', 'info', 'MFA validado', actor_username=user.username, mfa_status='success')
            audit_log('session_created', 'authentication', 'info', 'Sessão criada', actor_username=user.username)
            return _post_login_redirect(user)
        audit_log('mfa_validation_failure', 'authentication', 'warning', 'Código MFA inválido', actor_username=user.username, mfa_status='failure')
    return render_template('auth/mfa_verify.html')


@bp.route('/logout')
@login_required
def logout():
    audit_log('logout', 'authentication', 'info', 'Logout')
    logout_user()
    return redirect(url_for('auth.login'))
