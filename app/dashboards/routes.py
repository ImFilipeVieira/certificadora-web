import csv
import io
from datetime import datetime, timedelta
from flask import Blueprint, render_template, Response, redirect, url_for, request
from flask_login import login_required, current_user
from sqlalchemy import text
import plotly.graph_objects as go
import plotly.io as pio
from app import AuditSession, AppSession
from app.audit.logger import audit_log
from app.permissions.decorators import permission_required, has_any_permission

bp = Blueprint('dashboard', __name__)

def _scalar(db, sql, params=None, default=0):
    try:
        val = db.execute(text(sql), params or {}).scalar()
        return val if val is not None else default
    except Exception:
        return default

def _rows(db, sql, params=None):
    try:
        return db.execute(text(sql), params or {}).mappings().all()
    except Exception:
        return []

def _fig_html(fig, height=310):
    fig.update_layout(
        template='plotly_white',
        margin=dict(l=24, r=24, t=42, b=28),
        height=height,
        font=dict(family='Inter, Arial, sans-serif'),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        showlegend=True,
    )
    return pio.to_html(fig, include_plotlyjs='cdn', full_html=False, config={'displayModeBar': False, 'responsive': True})

def _parse_period(default_days=30):
    try:
        days = int(request.args.get('days', default_days))
        if days not in [1, 7, 30, 90, 180, 365]:
            days = default_days
    except Exception:
        days = default_days
    return days

@bp.route('/')
@login_required
def index():
    if not has_any_permission(current_user.id):
        audit_log('no_permissions_home', 'authorization', 'warning', 'Usuário autenticado sem nenhuma permissão acessou a página inicial', actor_user_id=current_user.id, actor_username=current_user.username, result='no_permissions')
        return redirect(url_for('dashboard.no_access'))

    db = AppSession()
    audit_db = AuditSession()
    now = datetime.utcnow()
    in_30 = now + timedelta(days=30)

    total_issued = _scalar(db, "SELECT COUNT(*) FROM certificates WHERE status='issued'")
    total_revoked = _scalar(db, "SELECT COUNT(*) FROM certificates WHERE status='revoked'")
    total_pending = _scalar(db, "SELECT COUNT(*) FROM certificate_requests WHERE status='pending'")
    total_rejected = _scalar(db, "SELECT COUNT(*) FROM certificate_requests WHERE status='rejected'")
    expiring_30 = _scalar(db, "SELECT COUNT(*) FROM certificates WHERE status='issued' AND not_after BETWEEN :now AND :in30", {'now': now, 'in30': in_30})
    expired = _scalar(db, "SELECT COUNT(*) FROM certificates WHERE status='issued' AND not_after < :now", {'now': now})
    downloads_30 = _scalar(audit_db, "SELECT COUNT(*) FROM logs_certificadora WHERE event_type='certificate_download_success' AND timestamp_utc >= :since", {'since': now - timedelta(days=30)})

    monthly = _rows(db, """
        SELECT DATE_FORMAT(created_at, '%Y-%m') AS month, COUNT(*) AS total
        FROM certificates
        WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 12 MONTH)
        GROUP BY DATE_FORMAT(created_at, '%Y-%m')
        ORDER BY month
    """)
    fig_issued = go.Figure()
    fig_issued.add_trace(go.Bar(x=[r['month'] for r in monthly], y=[r['total'] for r in monthly], name='Emitidos', marker_color='#0f766e'))
    fig_issued.update_layout(title='Certificados emitidos por mês', xaxis_title='Mês', yaxis_title='Quantidade')

    status_rows = _rows(db, "SELECT status, COUNT(*) AS total FROM certificate_requests GROUP BY status ORDER BY total DESC")
    fig_status = go.Figure(data=[go.Pie(labels=[r['status'] or 'indefinido' for r in status_rows], values=[r['total'] for r in status_rows], hole=.55)])
    fig_status.update_layout(title='Situação das solicitações')

    download_rows = _rows(audit_db, """
        SELECT JSON_UNQUOTE(JSON_EXTRACT(details_json, '$.format')) AS formato, COUNT(*) AS total
        FROM logs_certificadora
        WHERE event_type='certificate_download_success' AND timestamp_utc >= :since
        GROUP BY JSON_UNQUOTE(JSON_EXTRACT(details_json, '$.format'))
        ORDER BY total DESC LIMIT 10
    """, {'since': now - timedelta(days=90)})
    fig_downloads = go.Figure()
    fig_downloads.add_trace(go.Bar(x=[r['formato'] or 'indefinido' for r in download_rows], y=[r['total'] for r in download_rows], name='Downloads', marker_color='#1d4ed8'))
    fig_downloads.update_layout(title='Downloads por formato nos últimos 90 dias', xaxis_title='Formato', yaxis_title='Downloads')

    expiry_rows = _rows(db, """
        SELECT common_name, not_after, DATEDIFF(not_after, UTC_TIMESTAMP()) AS days_left
        FROM certificates
        WHERE status='issued' AND not_after >= UTC_TIMESTAMP() AND not_after <= DATE_ADD(UTC_TIMESTAMP(), INTERVAL 90 DAY)
        ORDER BY not_after ASC LIMIT 15
    """)
    fig_expiry = go.Figure()
    fig_expiry.add_trace(go.Bar(x=[r['days_left'] for r in expiry_rows], y=[r['common_name'] for r in expiry_rows], orientation='h', marker_color=['#dc2626' if (r['days_left'] or 0) <= 15 else '#d97706' if (r['days_left'] or 0) <= 30 else '#0f766e' for r in expiry_rows], name='Dias restantes'))
    fig_expiry.update_layout(title='Certificados próximos do vencimento — até 90 dias', xaxis_title='Dias restantes', yaxis_title='Certificado')

    recent_events = _rows(audit_db, "SELECT timestamp_utc, event_type, severity, actor_username, result, ip_address FROM logs_certificadora ORDER BY id DESC LIMIT 12")
    expiring_list = _rows(db, """
        SELECT id, common_name, serial, not_after, DATEDIFF(not_after, UTC_TIMESTAMP()) AS days_left
        FROM certificates
        WHERE status='issued' AND not_after >= UTC_TIMESTAMP() AND not_after <= DATE_ADD(UTC_TIMESTAMP(), INTERVAL 90 DAY)
        ORDER BY not_after ASC LIMIT 10
    """)

    insights = []
    if expired > 0: insights.append({'level': 'danger', 'title': 'Certificados vencidos', 'text': f'Existem {expired} certificado(s) emitido(s) já vencido(s). Priorize substituição/revogação.'})
    if expiring_30 > 0: insights.append({'level': 'warning', 'title': 'Vencimento próximo', 'text': f'{expiring_30} certificado(s) vencem nos próximos 30 dias. Recomendado iniciar renovação.'})
    if total_pending > 0: insights.append({'level': 'info', 'title': 'Fila de aprovação', 'text': f'Existem {total_pending} solicitação(ões) pendente(s) aguardando análise.'})
    if total_rejected > 0: insights.append({'level': 'warning', 'title': 'Solicitações negadas', 'text': f'Há {total_rejected} solicitação(ões) negada(s). Avalie padrões recorrentes de reprovação.'})
    if downloads_30 == 0 and total_issued > 0: insights.append({'level': 'info', 'title': 'Baixo uso recente', 'text': 'Não foram encontrados downloads nos últimos 30 dias, apesar de existirem certificados emitidos.'})
    if not insights: insights.append({'level': 'success', 'title': 'Ambiente saudável', 'text': 'Nenhum risco crítico detectado nos indicadores principais.'})

    dashboard = {
        'cards': {'issued': total_issued, 'revoked': total_revoked, 'pending': total_pending, 'rejected': total_rejected, 'expiring_30': expiring_30, 'downloads_30': downloads_30},
        'charts': {'issued_month': _fig_html(fig_issued), 'request_status': _fig_html(fig_status), 'downloads_format': _fig_html(fig_downloads), 'expiry': _fig_html(fig_expiry)},
        'insights': insights, 'recent_events': recent_events, 'expiring_list': expiring_list,
    }
    audit_log('home_dashboard_opened', 'dashboard', 'info', 'Dashboard inicial aberto', details={'cards': dashboard['cards']})
    return render_template('admin/index.html', dashboard=dashboard)

@bp.route('/no-access')
@login_required
def no_access():
    audit_log('no_access_page_viewed', 'authorization', 'warning', 'Página de usuário sem acesso exibida', actor_user_id=current_user.id, actor_username=current_user.username, result='no_permissions')
    return render_template('admin/no_access.html'), 403

@bp.route('/audit')
@login_required
@permission_required('audit.view')
def audit():
    days = _parse_period(30)
    since = datetime.utcnow() - timedelta(days=days)
    audit_db = AuditSession()

    filters = {
        'days': days,
        'user': request.args.get('user', '').strip(),
        'event_type': request.args.get('event_type', '').strip(),
        'severity': request.args.get('severity', '').strip(),
        'result': request.args.get('result', '').strip(),
        'ip': request.args.get('ip', '').strip(),
    }

    where = ["timestamp_utc >= :since"]
    params = {'since': since}
    if filters['user']:
        where.append("actor_username LIKE :user")
        params['user'] = f"%{filters['user']}%"
    if filters['event_type']:
        where.append("event_type LIKE :event_type")
        params['event_type'] = f"%{filters['event_type']}%"
    if filters['severity']:
        where.append("severity = :severity")
        params['severity'] = filters['severity']
    if filters['result']:
        where.append("result LIKE :result")
        params['result'] = f"%{filters['result']}%"
    if filters['ip']:
        where.append("ip_address LIKE :ip")
        params['ip'] = f"%{filters['ip']}%"
    where_sql = ' AND '.join(where)

    total_events = _scalar(audit_db, f"SELECT COUNT(*) FROM logs_certificadora WHERE {where_sql}", params)
    critical_events = _scalar(audit_db, f"SELECT COUNT(*) FROM logs_certificadora WHERE {where_sql} AND severity IN ('critical','error')", params)
    denied_events = _scalar(audit_db, f"SELECT COUNT(*) FROM logs_certificadora WHERE {where_sql} AND (result='denied' OR event_type='access_denied')", params)
    login_failures = _scalar(audit_db, f"SELECT COUNT(*) FROM logs_certificadora WHERE {where_sql} AND event_type IN ('login_password_failure','ldap_bind_failure','login_blocked','user_locked')", params)
    mfa_failures = _scalar(audit_db, f"SELECT COUNT(*) FROM logs_certificadora WHERE {where_sql} AND event_type='mfa_validation_failure'", params)
    downloads = _scalar(audit_db, f"SELECT COUNT(*) FROM logs_certificadora WHERE {where_sql} AND event_type='certificate_download_success'", params)

    timeline = _rows(audit_db, f"""
        SELECT DATE_FORMAT(timestamp_utc, '%Y-%m-%d') AS dia, COUNT(*) AS total
        FROM logs_certificadora
        WHERE {where_sql}
        GROUP BY DATE_FORMAT(timestamp_utc, '%Y-%m-%d')
        ORDER BY dia
    """, params)
    fig_timeline = go.Figure()
    fig_timeline.add_trace(go.Scatter(x=[r['dia'] for r in timeline], y=[r['total'] for r in timeline], mode='lines+markers', name='Eventos', line=dict(color='#0f766e', width=3)))
    fig_timeline.update_layout(title='Volume de eventos por dia', xaxis_title='Dia', yaxis_title='Eventos')

    categories = _rows(audit_db, f"""
        SELECT event_category, COUNT(*) AS total
        FROM logs_certificadora
        WHERE {where_sql}
        GROUP BY event_category
        ORDER BY total DESC
        LIMIT 10
    """, params)
    fig_categories = go.Figure(data=[go.Pie(labels=[r['event_category'] or 'indefinida' for r in categories], values=[r['total'] for r in categories], hole=.55)])
    fig_categories.update_layout(title='Eventos por categoria')

    severity_rows = _rows(audit_db, f"""
        SELECT severity, COUNT(*) AS total
        FROM logs_certificadora
        WHERE {where_sql}
        GROUP BY severity
        ORDER BY total DESC
    """, params)
    severity_colors = {'info': '#1d4ed8', 'warning': '#d97706', 'error': '#dc2626', 'critical': '#7f1d1d' }
    fig_severity = go.Figure()
    fig_severity.add_trace(go.Bar(x=[r['severity'] or 'indefinida' for r in severity_rows], y=[r['total'] for r in severity_rows], marker_color=[severity_colors.get(r['severity'], '#64748b') for r in severity_rows], name='Severidade'))
    fig_severity.update_layout(title='Eventos por severidade', xaxis_title='Severidade', yaxis_title='Eventos')

    top_users = _rows(audit_db, f"""
        SELECT COALESCE(actor_username, 'sistema') AS usuario, COUNT(*) AS total
        FROM logs_certificadora
        WHERE {where_sql}
        GROUP BY COALESCE(actor_username, 'sistema')
        ORDER BY total DESC
        LIMIT 10
    """, params)
    fig_users = go.Figure()
    fig_users.add_trace(go.Bar(x=[r['total'] for r in top_users], y=[r['usuario'] for r in top_users], orientation='h', marker_color='#1d4ed8', name='Eventos'))
    fig_users.update_layout(title='Usuários mais ativos', xaxis_title='Eventos', yaxis_title='Usuário')

    top_ips = _rows(audit_db, f"""
        SELECT COALESCE(ip_address, 'sem_ip') AS ip, COUNT(*) AS total
        FROM logs_certificadora
        WHERE {where_sql}
        GROUP BY COALESCE(ip_address, 'sem_ip')
        ORDER BY total DESC
        LIMIT 10
    """, params)
    fig_ips = go.Figure()
    fig_ips.add_trace(go.Bar(x=[r['ip'] for r in top_ips], y=[r['total'] for r in top_ips], marker_color='#0f766e', name='Eventos'))
    fig_ips.update_layout(title='Origem por IP', xaxis_title='IP', yaxis_title='Eventos')

    security_events = _rows(audit_db, f"""
        SELECT event_type, COUNT(*) AS total
        FROM logs_certificadora
        WHERE {where_sql}
          AND event_type IN ('login_password_failure','ldap_bind_failure','mfa_validation_failure','login_blocked','user_locked','access_denied','unhandled_exception')
        GROUP BY event_type
        ORDER BY total DESC
    """, params)
    fig_security = go.Figure()
    fig_security.add_trace(go.Bar(x=[r['event_type'] for r in security_events], y=[r['total'] for r in security_events], marker_color='#dc2626', name='Eventos críticos'))
    fig_security.update_layout(title='Eventos de segurança', xaxis_title='Evento', yaxis_title='Quantidade')

    recent_events = _rows(audit_db, f"""
        SELECT id, timestamp_utc, event_type, event_category, severity, actor_username, result, ip_address, endpoint, message
        FROM logs_certificadora
        WHERE {where_sql}
        ORDER BY id DESC
        LIMIT 300
    """, params)

    insights = []
    if critical_events > 0:
        insights.append({'level': 'danger', 'title': 'Eventos críticos detectados', 'text': f'Foram encontrados {critical_events} evento(s) error/critical no período. Verifique exceções, falhas e bloqueios.'})
    if login_failures >= 5:
        insights.append({'level': 'danger', 'title': 'Possível força bruta', 'text': f'Foram registradas {login_failures} falhas/bloqueios de login. Avalie IPs e usuários envolvidos.'})
    if mfa_failures > 0:
        insights.append({'level': 'warning', 'title': 'Falhas de MFA', 'text': f'{mfa_failures} falha(s) de MFA foram registradas. Pode indicar erro do usuário ou tentativa indevida.'})
    if denied_events > 0:
        insights.append({'level': 'warning', 'title': 'Acessos negados', 'text': f'{denied_events} tentativa(s) de acesso sem permissão. Revise perfis e comportamento.'})
    if downloads > 20:
        insights.append({'level': 'info', 'title': 'Alto volume de downloads', 'text': f'{downloads} downloads de certificado no período. Valide se está compatível com mudanças planejadas.'})
    if not insights:
        insights.append({'level': 'success', 'title': 'Auditoria saudável', 'text': 'Nenhum sinal crítico de segurança foi identificado no período filtrado.'})

    audit_dashboard = {
        'filters': filters,
        'cards': {
            'total_events': total_events,
            'critical_events': critical_events,
            'denied_events': denied_events,
            'login_failures': login_failures,
            'mfa_failures': mfa_failures,
            'downloads': downloads,
        },
        'charts': {
            'timeline': _fig_html(fig_timeline),
            'categories': _fig_html(fig_categories),
            'severity': _fig_html(fig_severity),
            'users': _fig_html(fig_users, height=360),
            'ips': _fig_html(fig_ips),
            'security': _fig_html(fig_security),
        },
        'insights': insights,
        'recent_events': recent_events,
        'top_users': top_users,
        'top_ips': top_ips,
    }

    audit_log('audit_dashboard_opened', 'audit', 'info', 'Dashboard avançado de auditoria aberto', details={'filters': filters, 'cards': audit_dashboard['cards']})
    return render_template('admin/audit.html', audit_dashboard=audit_dashboard)

@bp.route('/audit/export.csv')
@login_required
@permission_required('audit.export')
def audit_csv():
    audit_log('audit_log_exported', 'audit', 'info', 'CSV exportado')
    rows = AuditSession().execute(text('select * from logs_certificadora order by id desc limit 10000')).mappings().all()
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows([dict(r) for r in rows])
    return Response(buf.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=audit_logs.csv'})
