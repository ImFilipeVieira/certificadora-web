from functools import wraps
from flask import redirect, url_for, request
from flask_login import current_user
from sqlalchemy import text
from app import AppSession
from app.audit.logger import audit_log

def has_permission(user_id, code):
    db = AppSession()
    sql = text("""
        SELECT 1
        FROM user_groups ug
        JOIN group_permissions gp ON gp.group_id = ug.group_id
        JOIN permissions p ON p.id = gp.permission_id
        WHERE ug.user_id = :u AND p.code = :c
        LIMIT 1
    """)
    return db.execute(sql, {'u': user_id, 'c': code}).first() is not None

def user_permission_codes(user_id):
    db = AppSession()
    sql = text("""
        SELECT DISTINCT p.code
        FROM user_groups ug
        JOIN group_permissions gp ON gp.group_id = ug.group_id
        JOIN permissions p ON p.id = gp.permission_id
        WHERE ug.user_id = :u
        ORDER BY p.code
    """)
    return [r[0] for r in db.execute(sql, {'u': user_id}).all()]

def has_any_permission(user_id):
    return len(user_permission_codes(user_id)) > 0

def permission_required(code):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if not has_permission(current_user.id, code):
                audit_log(
                    'access_denied', 'authorization', 'warning',
                    'Acesso negado por falta de permissão',
                    actor_user_id=current_user.id,
                    actor_username=current_user.username,
                    result='denied',
                    details={'required_permission': code, 'endpoint_requested': request.path},
                )
                return redirect(url_for('dashboard.no_access'))
            return fn(*a, **kw)
        return wrapper
    return deco
