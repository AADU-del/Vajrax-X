"""
VAJRA-X — Basic Test Suite  (Bug #30)
Run: pytest tests/test_routes.py -v --cov=app
"""
import pytest
import json
from datetime import datetime, timezone


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def app():
    """Create a test Flask app with in-memory SQLite."""
    import os
    os.environ['FLASK_ENV'] = 'testing'

    from app import app as flask_app, create_app
    from database.db import db
    from database.models import User, Detection, Log

    flask_app.config.update({
        'TESTING':                  True,
        'SQLALCHEMY_DATABASE_URI':  'sqlite:///:memory:',
        'WTF_CSRF_ENABLED':         False,
        'RATELIMIT_ENABLED':        False,     # Disable rate limiting in tests
        'SECRET_KEY':               'test-secret-key-do-not-use-in-prod',
    })

    with flask_app.app_context():
        db.create_all()

        # Seed a test user
        from werkzeug.security import generate_password_hash
        test_user = User(
            username='testadmin',
            password_hash=generate_password_hash('TestPass1234!'),
            role='admin'
        )
        db.session.add(test_user)

        # Seed some detections
        for i in range(5):
            det = Detection(
                module_name='smart_city',
                object_detected=f'person_{i}',
                confidence=0.85,
                threat_level='LOW' if i < 3 else 'HIGH',
                timestamp=datetime.now(timezone.utc)
            )
            db.session.add(det)

        db.session.commit()

    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """A test client that is already logged in as testadmin."""
    with client.session_transaction() as sess:
        sess['user_id'] = 1

    # Use API login instead
    resp = client.post('/api/auth/login', json={
        'username': 'testadmin',
        'password': 'TestPass1234!'
    })
    return client


# ── Unauthenticated access tests ─────────────────────────────────────────────

class TestUnauthenticated:
    def test_root_redirects_to_login(self, client):
        """GET / should redirect unauthenticated user to /login."""
        resp = client.get('/', follow_redirects=False)
        assert resp.status_code in (302, 301)
        assert 'login' in resp.headers.get('Location', '').lower()

    def test_dashboard_requires_auth(self, client):
        """GET /dashboard should redirect unauthenticated user."""
        resp = client.get('/dashboard', follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_api_stats_requires_auth(self, client):
        """GET /api/stats should return 401 without auth."""
        resp = client.get('/api/stats')
        assert resp.status_code == 401

    def test_api_detections_requires_auth(self, client):
        """GET /api/detections should return 401 without auth."""
        resp = client.get('/api/detections')
        assert resp.status_code == 401

    def test_health_endpoint_public(self, client):
        """GET /health should be publicly accessible — Bug #24."""
        resp = client.get('/health')
        assert resp.status_code in (200, 503)
        data = resp.get_json()
        assert 'status' in data
        assert 'database' in data
        assert 'timestamp' in data

    def test_404_returns_json_for_api(self, client):
        """GET /api/nonexistent should return JSON 404."""
        resp = client.get('/api/nonexistent_endpoint_xyz')
        assert resp.status_code == 404
        data = resp.get_json()
        assert data is not None
        assert 'error' in data


# ── Authentication tests ──────────────────────────────────────────────────────

class TestAuth:
    def test_login_page_renders(self, client):
        """GET /login should return 200."""
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_login_with_valid_credentials(self, client):
        """POST /api/auth/login with correct creds should return success."""
        resp = client.post('/api/auth/login', json={
            'username': 'testadmin',
            'password': 'TestPass1234!'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('status') == 'success'

    def test_login_with_wrong_password(self, client):
        """POST /api/auth/login with bad password should return 401."""
        resp = client.post('/api/auth/login', json={
            'username': 'testadmin',
            'password': 'wrongpassword'
        })
        assert resp.status_code == 401
        data = resp.get_json()
        assert data.get('status') == 'error'

    def test_login_with_nonexistent_user(self, client):
        """POST /api/auth/login with unknown user should return 401."""
        resp = client.post('/api/auth/login', json={
            'username': 'ghost_user_xyz',
            'password': 'anypassword'
        })
        assert resp.status_code == 401

    def test_register_with_existing_username(self, auth_client):
        """POST /api/auth/register with duplicate username should fail."""
        resp = auth_client.post('/api/auth/register', json={
            'username': 'testadmin',
            'password': 'SomePass1234!'
        })
        assert resp.status_code in (400, 409)

    def test_register_rejects_weak_password(self, client):
        """Registration should reject weak passwords."""
        resp = client.post('/api/auth/register', json={
            'username': 'weakuser',
            'password': 'weakpass'
        })
        assert resp.status_code == 400
        data = resp.get_json()
        assert data.get('status') == 'error'

    def test_change_password_success(self, auth_client):
        """POST /api/auth/change_password with correct current password should succeed."""
        # Seeded testadmin password is TestPass1234!
        resp = auth_client.post('/api/auth/change_password', json={
            'current_password': 'TestPass1234!',
            'new_password': 'NewSecurePass123!'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('status') == 'success'
        
        # Restore original password to avoid breaking other tests using the auth_client fixture
        resp = auth_client.post('/api/auth/change_password', json={
            'current_password': 'NewSecurePass123!',
            'new_password': 'TestPass1234!'
        })
        assert resp.status_code == 200

    def test_change_password_wrong_current(self, auth_client):
        """POST /api/auth/change_password with wrong current password should return 401."""
        resp = auth_client.post('/api/auth/change_password', json={
            'current_password': 'wrongpassword',
            'new_password': 'NewSecurePass123!'
        })
        assert resp.status_code == 401

    def test_change_password_validation_failure(self, auth_client):
        """POST /api/auth/change_password with too short new password should return 400."""
        resp = auth_client.post('/api/auth/change_password', json={
            'current_password': 'TestPass1234!',
            'new_password': 'short'
        })
        assert resp.status_code == 400


# ── API tests (authenticated) ─────────────────────────────────────────────────

class TestAPIAuthenticated:
    def test_api_stats_returns_correct_shape(self, auth_client):
        """GET /api/stats should return total, by_module, by_threat — Bug #2."""
        resp = auth_client.get('/api/stats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'total' in data
        assert 'by_module' in data
        assert 'by_threat' in data
        # Bug #2: by_threat should be a DICT, not a list
        assert isinstance(data['by_threat'], dict)
        assert data['total'] >= 5  # We seeded 5

    def test_api_detections_paginated(self, auth_client):
        """GET /api/detections should return paginated {data, pagination} — Bug #15."""
        resp = auth_client.get('/api/detections?limit=2&page=1')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'data' in data
        assert 'pagination' in data
        assert 'total' in data['pagination']
        assert 'pages' in data['pagination']
        assert len(data['data']) <= 2

    def test_api_detections_module_filter(self, auth_client):
        """GET /api/detections?module=smart_city should only return that module."""
        resp = auth_client.get('/api/detections?module=smart_city')
        assert resp.status_code == 200
        data = resp.get_json()
        for det in data['data']:
            assert det['module_name'] == 'smart_city'

    def test_api_analytics_returns_structure(self, auth_client):
        """GET /api/analytics should return all expected keys."""
        resp = auth_client.get('/api/analytics')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'trends' in data
        assert 'threats' in data
        assert 'modules' in data
        assert 'confidence' in data
        assert 'metrics' in data
        assert 'detections' in data

    def test_api_analytics_date_filter(self, auth_client):
        """GET /api/analytics?from=&to= should accept date params — Bug #8."""
        today = datetime.now().strftime('%Y-%m-%d')
        resp  = auth_client.get(f'/api/analytics?from=2020-01-01&to={today}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_api_settings_get(self, auth_client):
        """GET /api/settings should return current settings — Bug #7."""
        resp = auth_client.get('/api/settings')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'settings' in data
        s = data['settings']
        assert 'conf_threshold' in s
        assert 'fps_limit' in s

    def test_api_settings_update(self, auth_client):
        """POST /api/settings should update and return new values — Bug #7."""
        resp = auth_client.post('/api/settings', json={
            'conf_threshold': 0.55,
            'fps_limit': 20
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['settings']['conf_threshold'] == pytest.approx(0.55, abs=0.01)
        assert data['settings']['fps_limit'] == 20

    def test_api_settings_rejects_invalid_values(self, auth_client):
        """POST /api/settings with out-of-range values should be clamped."""
        resp = auth_client.post('/api/settings', json={
            'conf_threshold': 5.0,   # > 0.99, should be clamped
            'fps_limit': 999,         # > 60, should be clamped
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['settings']['conf_threshold'] <= 0.99
        assert data['settings']['fps_limit'] <= 60


# ── Detection Engine tests ────────────────────────────────────────────────────

class TestDetectionEngine:
    def test_compute_trends_handles_datetime(self):
        """Bug #3: compute_trends() should not crash on datetime timestamps."""
        from app import compute_trends
        dets = [
            {'timestamp': datetime(2026, 6, 12, 14, 0, 0), 'threat_level': 'LOW'},
            {'timestamp': datetime(2026, 6, 12, 15, 0, 0), 'threat_level': 'HIGH'},
            {'timestamp': datetime(2026, 6, 12, 15, 30, 0), 'threat_level': 'LOW'},
        ]
        result = compute_trends(dets)   # Should NOT throw TypeError
        assert 'labels' in result
        assert 'values' in result
        assert len(result['labels']) == len(result['values'])

    def test_compute_metrics_handles_datetime(self):
        """Bug #3: compute_metrics() should not crash on datetime timestamps."""
        from app import compute_metrics
        dets = [
            {'timestamp': datetime(2026, 6, 12, 14, 0), 'threat_level': 'LOW',  'confidence': 0.9,  'module_name': 'smart_city'},
            {'timestamp': datetime(2026, 6, 12, 14, 0), 'threat_level': 'HIGH', 'confidence': 0.75, 'module_name': 'border'},
        ]
        result = compute_metrics(dets)   # Should NOT throw TypeError
        assert 'peakHour'  in result
        assert 'avgPerHour' in result
        assert 'alertRate'  in result
        # Bug #27: avgAccuracy should be a string like "82.5%" with decimal
        assert '.' in result['avgAccuracy']

    def test_compute_threats_handles_none_level(self):
        """compute_threats() should not crash when threat_level is None."""
        from app import compute_threats
        dets = [
            {'threat_level': None},
            {'threat_level': 'HIGH'},
            {'threat_level': 'LOW'},
        ]
        result = compute_threats(dets)
        assert result['high'] == 1
        assert result['low'] == 1


# ── Config tests ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_secret_key_is_not_hardcoded(self):
        """Bug #13: SECRET_KEY must not be the legacy hardcoded dev value."""
        from config import get_config
        cfg = get_config()
        assert cfg.SECRET_KEY != 'dev-key-change-in-production'
        assert len(cfg.SECRET_KEY) >= 32

    def test_production_config_rejects_placeholder_secrets(self, monkeypatch):
        """Production config should fail fast on placeholder secrets."""
        import os
        monkeypatch.setenv('FLASK_ENV', 'production')
        monkeypatch.setenv('SECRET_KEY', 'change-me')
        monkeypatch.setenv('JWT_SECRET_KEY', 'change-me')
        monkeypatch.setenv('ADMIN_USERNAME', 'admin')
        monkeypatch.setenv('ADMIN_PASSWORD', 'weakpass')
        from config import get_config
        with pytest.raises(RuntimeError):
            get_config()

    def test_db_indexes_defined(self):
        """Bug #14: Critical columns should have DB indexes."""
        from database.models import Detection, User
        det_cols = {c.name: c for c in Detection.__table__.columns}
        assert det_cols['timestamp'].index is True, "Detection.timestamp missing index"
        assert det_cols['threat_level'].index is True, "Detection.threat_level missing index"
        assert det_cols['module_name'].index is True, "Detection.module_name missing index"


class TestAICopilot:
    def test_copilot_requires_auth(self, client):
        """POST /api/ai/copilot should redirect or fail with 401 without auth."""
        resp = client.post('/api/ai/copilot', json={'message': 'test query'})
        assert resp.status_code == 401

    def test_copilot_missing_message(self, auth_client):
        """POST /api/ai/copilot with empty message should return 400."""
        resp = auth_client.post('/api/ai/copilot', json={'message': ''})
        assert resp.status_code == 400

    def test_copilot_local_fallback(self, auth_client, monkeypatch):
        """POST /api/ai/copilot returns successful fallback response when no Groq key."""
        from app import cfg
        monkeypatch.setattr(cfg, 'GROQ_API_KEY', None)

        resp = auth_client.post('/api/ai/copilot', json={'message': 'Summarize threats'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'message' in data
        assert data['provider'] == 'local_fallback'
