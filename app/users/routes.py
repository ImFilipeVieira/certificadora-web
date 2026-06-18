from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from sqlalchemy import text
from app import AppSession
from app.models import User, Group, UserGroup, Permission, GroupPermission
from app.permissions.decorators import permission_required
from app.audit.logger import audit_log

bp = Blueprint('users', __name__, url_prefix='/users')

@bp.route('/')
@login_required
@permission_required('users.manage')
def list_users():
    db=AppSession(); users=db.query(User).order_by(User.username.asc()).all(); groups=db.query(Group).order_by(Group.name.asc()).all(); rows=[]
    group_names_by_id = {g.id: g.name for g in groups}
    user_group_rows = db.execute(text('SELECT user_id, group_id FROM user_groups')).all()
    groups_by_user = {}
    for user_id, group_id in user_group_rows:
        groups_by_user.setdefault(user_id, []).append(group_id)
    for u in users:
        gids=groups_by_user.get(u.id, [])
        rows.append({'user':u,'group_ids':gids,'group_names':[group_names_by_id.get(gid) for gid in gids if gid in group_names_by_id]})
    audit_log('user_admin_opened','users','info','Tela compacta de usuários aberta')
    return render_template('admin/users.html', rows=rows, groups=groups)

@bp.route('/groups')
@login_required
@permission_required('groups.manage')
def groups_page():
    db=AppSession(); groups=db.query(Group).order_by(Group.name.asc()).all(); permissions=db.query(Permission).order_by(Permission.description.asc(), Permission.code.asc()).all(); group_rows=[]
    group_permission_rows = db.execute(text('SELECT group_id, permission_id FROM group_permissions')).all()
    permissions_by_group = {}
    for group_id, permission_id in group_permission_rows:
        permissions_by_group.setdefault(group_id, []).append(permission_id)
    for g in groups:
        pids=permissions_by_group.get(g.id, [])
        group_rows.append({'group':g,'permission_ids':pids,'permission_count':len(pids)})
    audit_log('permission_groups_opened','users','info','Tela compacta de grupos aberta')
    return render_template('admin/permission_groups.html', groups=groups, permissions=permissions, group_rows=group_rows)

@bp.route('/groups/create', methods=['POST'])
@login_required
@permission_required('groups.manage')
def create_group():
    db=AppSession(); name=(request.form.get('name') or '').strip(); description=(request.form.get('description') or '').strip()
    if not name: flash('Informe o nome do grupo.'); return redirect(url_for('users.groups_page'))
    if db.query(Group).filter_by(name=name).first(): flash('Já existe um grupo com esse nome.'); return redirect(url_for('users.groups_page'))
    g=Group(name=name, description=description); db.add(g); db.commit(); audit_log('group_created','users','warning','Grupo criado',resource_type='group',resource_id=str(g.id),resource_name=g.name); flash(f'Grupo {name} criado com sucesso.'); return redirect(url_for('users.groups_page'))

@bp.route('/groups/<int:gid>/update', methods=['POST'])
@login_required
@permission_required('groups.manage')
def update_group(gid):
    db=AppSession(); g=db.get(Group,gid)
    if not g: flash('Grupo não encontrado.'); return redirect(url_for('users.groups_page'))
    new_name=(request.form.get('name') or '').strip(); description=(request.form.get('description') or '').strip(); selected=set(int(x) for x in request.form.getlist('permission_ids') if x.isdigit())
    if not new_name: flash('Informe o nome do grupo.'); return redirect(url_for('users.groups_page'))
    if db.query(Group).filter(Group.name==new_name, Group.id!=gid).first(): flash('Já existe outro grupo com esse nome.'); return redirect(url_for('users.groups_page'))
    g.name=new_name; g.description=description; db.execute(text('DELETE FROM group_permissions WHERE group_id=:gid'), {'gid':gid})
    for pid in selected: db.add(GroupPermission(group_id=gid, permission_id=pid))
    db.commit(); audit_log('group_updated','users','warning','Grupo atualizado',resource_type='group',resource_id=str(gid),resource_name=g.name); flash('Grupo atualizado com sucesso.'); return redirect(url_for('users.groups_page'))

@bp.route('/<int:uid>/groups', methods=['POST'])
@login_required
@permission_required('groups.manage')
def update_user_groups(uid):
    db=AppSession(); u=db.get(User,uid)
    if not u: flash('Usuário não encontrado'); return redirect(url_for('users.list_users'))
    selected=set(int(x) for x in request.form.getlist('group_ids') if x.isdigit()); db.execute(text('DELETE FROM user_groups WHERE user_id=:uid'), {'uid':uid})
    for gid in selected: db.add(UserGroup(user_id=uid, group_id=gid))
    db.commit(); audit_log('user_groups_updated','users','warning','Grupos do usuário atualizados',resource_type='user',resource_id=str(uid),resource_name=u.username); flash(f'Grupos atualizados para {u.username}'); return redirect(url_for('users.list_users'))

@bp.route('/<int:uid>/reset-mfa', methods=['POST'])
@login_required
@permission_required('mfa.reset')
def reset_mfa(uid):
    db=AppSession(); u=db.get(User,uid)
    if not u: flash('Usuário não encontrado'); return redirect(url_for('users.list_users'))
    u.mfa_secret=None; u.mfa_enabled=False; db.commit(); audit_log('mfa_reset_by_admin','users','warning','MFA resetado por administrador',resource_type='user',resource_id=str(uid),resource_name=u.username); return redirect(url_for('users.list_users'))

@bp.route('/<int:uid>/unlock', methods=['POST'])
@login_required
@permission_required('users.manage')
def unlock_user(uid):
    db=AppSession(); u=db.get(User,uid)
    if not u: flash('Usuário não encontrado'); return redirect(url_for('users.list_users'))
    u.failed_login_attempts=0; u.locked_until=None; db.commit(); audit_log('user_unlocked','users','warning','Usuário desbloqueado',resource_type='user',resource_id=str(uid),resource_name=u.username); return redirect(url_for('users.list_users'))

@bp.route('/<int:uid>/disable', methods=['POST'])
@login_required
@permission_required('users.manage')
def disable_user(uid):
    db=AppSession(); u=db.get(User,uid)
    if u: u.enabled=False; db.commit(); audit_log('user_disabled','users','warning','Usuário desabilitado',resource_type='user',resource_id=str(uid),resource_name=u.username)
    return redirect(url_for('users.list_users'))

@bp.route('/<int:uid>/enable', methods=['POST'])
@login_required
@permission_required('users.manage')
def enable_user(uid):
    db=AppSession(); u=db.get(User,uid)
    if u: u.enabled=True; db.commit(); audit_log('user_enabled','users','info','Usuário habilitado',resource_type='user',resource_id=str(uid),resource_name=u.username)
    return redirect(url_for('users.list_users'))
