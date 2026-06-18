import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, get_flashed_messages
from flask_login import LoginManager

from app.certificates import routes
from app.models import Certificate, CertificateGroup, localnow


def _view(fn):
    return fn.__wrapped__.__wrapped__


class FakeQuery:
    def __init__(self, db, model, rows):
        self.db = db
        self.model = model
        self.rows = list(rows)
        self.filters = {}

    def order_by(self, *args):
        if self.model is Certificate:
            self.rows.sort(key=lambda c: (c.not_after or localnow(), c.common_name or ''))
        if self.model is CertificateGroup:
            self.rows.sort(key=lambda g: g.name or '')
        return self

    def limit(self, count):
        self.rows = self.rows[:count]
        return self

    def all(self):
        return list(self.rows)

    def first(self):
        rows = self.all()
        return rows[0] if rows else None

    def count(self):
        return len(self.rows)

    def update(self, values):
        for row in self.rows:
            for key, value in values.items():
                setattr(row, key, value)
        return len(self.rows)

    def filter_by(self, **kwargs):
        self.rows = [
            row for row in self.rows
            if all(getattr(row, key) == value for key, value in kwargs.items())
        ]
        return self

    def filter(self, *criteria):
        for criterion in criteria:
            text = str(criterion)
            if self.model is Certificate and 'certificates.group_id IS NULL' in text:
                self.rows = [row for row in self.rows if row.group_id is None]
            elif self.model is Certificate and 'certificates.group_id' in text:
                value = _criterion_value(criterion)
                self.rows = [row for row in self.rows if row.group_id == value]
            elif self.model is CertificateGroup and 'certificate_groups.name' in text:
                value = _criterion_value(criterion)
                self.rows = [row for row in self.rows if row.name == value]
            elif self.model is CertificateGroup and 'certificate_groups.id' in text:
                value = _criterion_value(criterion)
                self.rows = [row for row in self.rows if row.id != value]
        return self


def _criterion_value(criterion):
    right = getattr(criterion, 'right', None)
    return getattr(right, 'value', None)


class FakeDB:
    def __init__(self, certificates=None, groups=None):
        self.certificates = list(certificates or [])
        self.groups = list(groups or [])
        self.added = []
        self.deleted = []
        self.committed = False

    def query(self, model):
        if model is Certificate:
            return FakeQuery(self, model, self.certificates)
        if model is CertificateGroup:
            return FakeQuery(self, model, self.groups)
        raise AssertionError(f'unexpected model: {model}')

    def get(self, model, row_id):
        rows = self.certificates if model is Certificate else self.groups
        return next((row for row in rows if row.id == row_id), None)

    def add(self, row):
        self.added.append(row)
        if isinstance(row, CertificateGroup):
            row.id = row.id or (max([g.id for g in self.groups] or [0]) + 1)
            self.groups.append(row)

    def flush(self):
        pass

    def commit(self):
        self.committed = True

    def delete(self, row):
        self.deleted.append(row)
        if isinstance(row, CertificateGroup):
            self.groups = [group for group in self.groups if group.id != row.id]


class CertificateMonitoringTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__, template_folder='../app/templates', static_folder='../app/static')
        self.app.config.update(SECRET_KEY='test', TESTING=True)
        self.app.jinja_env.globals['csrf_token'] = lambda: 'csrf-test-token'
        self.app.register_blueprint(routes.bp)
        login_manager = LoginManager()
        login_manager.init_app(self.app)

        @login_manager.user_loader
        def load_user(user_id):
            return None

    def cert(self, cert_id, common_name, days, group_id=None, status='issued'):
        return Certificate(
            id=cert_id,
            common_name=common_name,
            serial=f'serial-{cert_id}',
            fingerprint=f'fingerprint-{cert_id}',
            issuer='CA Interna',
            not_before=localnow() - timedelta(days=30),
            not_after=localnow() + timedelta(days=days),
            group_id=group_id,
            status=status,
            source='issued',
            algorithm='RSA 2048',
        )

    def group(self, group_id, name):
        return CertificateGroup(id=group_id, name=name, description='')

    def render_monitoring(self, db, path='/certificates/monitoring'):
        with patch.object(routes, 'AppSession', return_value=db), self.app.test_request_context(path):
            return _view(routes.monitoring)()

    def test_monitoring_renders_certificates_summary_and_assignment_form(self):
        db = FakeDB(
            certificates=[
                self.cert(1, 'api.internal.example.com', 5, group_id=10),
                self.cert(2, 'portal.internal.example.com', 120),
            ],
            groups=[self.group(10, 'Sistemas Internos')],
        )

        html = self.render_monitoring(db)

        self.assertIn('Certificados monitorados', html)
        self.assertIn('api.internal.example.com', html)
        self.assertIn('portal.internal.example.com', html)
        self.assertIn('Sistemas Internos', html)
        self.assertIn('/certificates/1/group', html)
        self.assertIn('2 monitorado(s)', html)

    def test_monitoring_filters_status_and_period_after_loading_certificates(self):
        db = FakeDB(
            certificates=[
                self.cert(1, 'expiring.example.com', 3),
                self.cert(2, 'valid.example.com', 120),
                self.cert(3, 'expired.example.com', -1),
            ]
        )

        html = self.render_monitoring(db, '/certificates/monitoring?status=expiring&period=7')

        self.assertIn('expiring.example.com', html)
        self.assertNotIn('valid.example.com', html)
        self.assertNotIn('expired.example.com', html)
        self.assertIn('1 monitorado(s)', html)

    def test_monitoring_searches_by_common_name_and_issuer(self):
        issuer_match = self.cert(1, 'gateway.example.com', 120)
        issuer_match.issuer = 'CA Financeira'
        db = FakeDB(
            certificates=[
                issuer_match,
                self.cert(2, 'portal.internal.example.com', 120),
            ]
        )

        html = self.render_monitoring(db, '/certificates/monitoring?q=financeira')

        self.assertIn('gateway.example.com', html)
        self.assertNotIn('portal.internal.example.com', html)
        self.assertIn('1 monitorado(s)', html)

    def test_monitoring_paginates_results(self):
        db = FakeDB(
            certificates=[
                self.cert(cert_id, f'cert-{cert_id:02d}.example.com', cert_id + 30)
                for cert_id in range(1, 31)
            ]
        )

        html = self.render_monitoring(db, '/certificates/monitoring?page=2')

        self.assertIn('Página 2 de 2', html)
        self.assertIn('cert-26.example.com', html)
        self.assertNotIn('cert-01.example.com', html)

    def test_monitoring_renders_empty_state_when_no_rows_match(self):
        db = FakeDB(certificates=[self.cert(1, 'valid.example.com', 120)])

        html = self.render_monitoring(db, '/certificates/monitoring?status=expired')

        self.assertIn('Nenhum certificado encontrado para os filtros selecionados.', html)
        self.assertIn('0 monitorado(s)', html)

    def test_create_group_requires_name(self):
        db = FakeDB()

        with patch.object(routes, 'AppSession', return_value=db), self.app.test_request_context(
            '/certificates/groups/create', method='POST', data={'name': '   '}
        ):
            response = _view(routes.create_certificate_group)()
            messages = get_flashed_messages()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(messages, ['Informe o nome do grupo de certificados.'])
        self.assertFalse(db.committed)

    def test_create_group_persists_valid_group(self):
        db = FakeDB()

        with patch.object(routes, 'AppSession', return_value=db), patch.object(routes, 'audit_log'), self.app.test_request_context(
            '/certificates/groups/create',
            method='POST',
            data={'name': 'ERP', 'description': 'Ambiente ERP'},
        ):
            response = _view(routes.create_certificate_group)()
            messages = get_flashed_messages()

        self.assertEqual(response.status_code, 302)
        self.assertTrue(db.committed)
        self.assertEqual(db.groups[0].name, 'ERP')
        self.assertEqual(messages, ['Grupo de certificados criado com sucesso.'])

    def test_assignment_to_existing_group_updates_certificate(self):
        cert = self.cert(1, 'api.example.com', 30)
        db = FakeDB(certificates=[cert], groups=[self.group(10, 'ERP')])

        with patch.object(routes, 'AppSession', return_value=db), patch.object(routes, 'audit_log'), self.app.test_request_context(
            '/certificates/1/group',
            method='POST',
            data={'group_id': '10'},
        ):
            response = _view(routes.update_certificate_group_assignment)(1)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(db.committed)
        self.assertEqual(cert.group_id, 10)

    def test_assignment_with_unknown_group_id_silently_clears_group_current_behavior(self):
        cert = self.cert(1, 'api.example.com', 30, group_id=10)
        db = FakeDB(certificates=[cert], groups=[self.group(10, 'ERP')])

        with patch.object(routes, 'AppSession', return_value=db), patch.object(routes, 'audit_log'), self.app.test_request_context(
            '/certificates/1/group',
            method='POST',
            data={'group_id': '999'},
        ):
            response = _view(routes.update_certificate_group_assignment)(1)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(db.committed)
        self.assertIsNone(cert.group_id)


if __name__ == '__main__':
    unittest.main()

