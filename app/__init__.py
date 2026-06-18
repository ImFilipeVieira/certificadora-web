import logging, os, re
from logging.handlers import RotatingFileHandler
from flask import Flask, request, send_from_directory, abort
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from .config import Config
login_manager=LoginManager(); csrf=CSRFProtect(); AppSession=None; AuditSession=None


def _prepare_demo_database(app_engine, audit_engine):
    if not Config.DEMO_MODE:
        return
    from .models import Base
    Base.metadata.create_all(app_engine)
    Base.metadata.create_all(audit_engine)

def create_app():
    global AppSession, AuditSession
    app=Flask(__name__); app.config.from_object(Config)
    os.makedirs('logs', exist_ok=True); os.makedirs('assets', exist_ok=True)
    handler=RotatingFileHandler('logs/certificadora.log', maxBytes=5000000, backupCount=10)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    app.logger.addHandler(handler); app.logger.setLevel(logging.INFO)
    app_engine=create_engine(Config.APP_DATABASE_URI, pool_pre_ping=True, future=True)
    audit_engine=create_engine(Config.AUDIT_DATABASE_URI, pool_pre_ping=True, future=True)
    _prepare_demo_database(app_engine, audit_engine)
    AppSession=scoped_session(sessionmaker(bind=app_engine))
    AuditSession=scoped_session(sessionmaker(bind=audit_engine))
    login_manager.init_app(app); login_manager.login_view='auth.login'; login_manager.login_message='Faça login para continuar.'; csrf.init_app(app)
    def _assets_dir(): return os.path.abspath(os.path.join(app.root_path, '..', 'assets'))
    @app.route('/assets/<path:filename>')
    def assets(filename):
        d=_assets_dir(); full=os.path.abspath(os.path.join(d, filename))
        if not full.startswith(d) or not os.path.exists(full): abort(404)
        return send_from_directory(d, filename)


    def format_datetime_br(value):
        if value in (None, '', '-'):
            return value or ''
        from datetime import datetime, timedelta
        text = str(value).strip()
        base = text.replace('T', ' ').replace('Z', '')
        try:
            dt = datetime.fromisoformat(base)
        except Exception:
            try:
                dt = datetime.strptime(base[:19], '%Y-%m-%d %H:%M:%S')
            except Exception:
                return value
        dt = dt - timedelta(hours=3)
        return dt.strftime('%Y-%m-%d %H:%M:%S')

    app.jinja_env.filters['br_time'] = format_datetime_br

    @app.route('/favicon.ico')
    def favicon():
        d=_assets_dir()
        if os.path.exists(os.path.join(d,'favicon.ico')): return send_from_directory(d,'favicon.ico',mimetype='image/x-icon')
        if os.path.exists(os.path.join(d,'logo.png')): return send_from_directory(d,'logo.png',mimetype='image/png')
        abort(404)
    @app.after_request
    def track_certificate_download(response):
        try:
            m=re.match(r'^/certificates/(\d+)/download/([A-Za-z0-9_\-]+)$', request.path or '')
            if m:
                from .models import CertificateDownload, utcnow
                db=AppSession(); cert_id=int(m.group(1)); fmt=m.group(2).lower(); result='success' if 200 <= response.status_code < 400 else f'failure:{response.status_code}'
                db.add(CertificateDownload(certificate_id=cert_id,user_id=current_user.id if getattr(current_user,'is_authenticated',False) else None,format=fmt,result=result,ip_address=request.remote_addr,user_agent=request.headers.get('User-Agent'),created_at=utcnow())); db.commit()
        except Exception as exc:
            try:
                from .audit.logger import audit_log
                audit_log('certificate_download_db_log_failed','certificates','warning','Falha ao registrar download no banco operacional', result='failure', reason=str(exc)[:500])
            except Exception: pass
        return response
    from .auth.routes import bp as auth_bp
    from .certificates.routes import bp as cert_bp
    from .users.routes import bp as users_bp
    from .dashboards.routes import bp as dash_bp
    app.register_blueprint(auth_bp); app.register_blueprint(cert_bp); app.register_blueprint(users_bp); app.register_blueprint(dash_bp)
    from .audit.logger import audit_log
    from .certificates.ca_utils import check_ca_files
    from .certificates.schema import ensure_certificate_monitoring_schema
    with app.app_context(): audit_log('app_started','system','info','Aplicação iniciada'); check_ca_files(); (None if Config.DEMO_MODE else ensure_certificate_monitoring_schema())
    @app.teardown_appcontext
    def cleanup(exc=None):
        if AppSession: AppSession.remove()
        if AuditSession: AuditSession.remove()
    @app.errorhandler(Exception)
    def err(e):
        if getattr(e,'code',None)==404: return e
        audit_log('unhandled_exception','system','error',str(e)[:1000], details={'endpoint':getattr(request,'endpoint',None)}); raise e


    # Rota interna de documentação - segura, sem blueprint adicional e sem dependência de auditoria/permissões.
    from flask_login import login_required as _docs_login_required
    from flask import render_template as _docs_render_template

    @app.route('/documentation/')
    @_docs_login_required
    def internal_documentation_page():
        return _docs_render_template('docs/index.html')

    return app
