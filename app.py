"""
VAJRA-X: Multi-Domain Situational Awareness Platform
Main Flask Application
"""
import secrets
import os
import cv2
import base64
import math
import io
import re
import requests as req_lib
import numpy as np
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify
)
from flask_login import LoginManager, login_required, current_user, logout_user
from flask_socketio import SocketIO, emit
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from sqlalchemy import func, cast, Date
from database.db import db
from database.models import User, Detection, Log
# Legacy raw-SQLite layer fully removed — app uses SQLAlchemy exclusively (Bug #5)
from modules.detection_engine import DetectionEngine
from config import get_config, Config
from auth import auth_bp, login_manager
from auth.decorators import admin_required
import threading
import time
import logging

# ── LOGGING SETUP ─────────────────────────────────────────
# Bug #23: Configure both console and rotating file handler
cfg: Config = get_config()
cfg.ensure_directories()
cfg.warn_if_default_admin_credentials()

logging.basicConfig(
    level=getattr(logging, cfg.LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add rotating file handler
_file_handler = RotatingFileHandler(
    cfg.LOG_FILE,
    maxBytes=10 * 1024 * 1024,   # 10 MB per file
    backupCount=5
)
_file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s'
))
logging.getLogger().addHandler(_file_handler)

# ── FLASK APP INIT ─────────────────────────────────────────
BASE_DIR: Path = Path(__file__).parent
app = Flask(
    __name__,
    static_folder=str(BASE_DIR / 'static'),
    template_folder=str(BASE_DIR / 'templates')
)

# Apply configuration
app.secret_key = cfg.SECRET_KEY
app.config['UPLOAD_FOLDER'] = str(cfg.UPLOAD_FOLDER)
app.config['PROCESSED_FOLDER'] = str(cfg.PROCESSED_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = cfg.MAX_CONTENT_LENGTH
app.config['SQLALCHEMY_DATABASE_URI'] = cfg.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = cfg.SQLALCHEMY_TRACK_MODIFICATIONS
app.config['SESSION_COOKIE_HTTPONLY'] = cfg.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SAMESITE'] = cfg.SESSION_COOKIE_SAMESITE
app.config['SESSION_COOKIE_SECURE'] = cfg.SESSION_COOKIE_SECURE
# Rate limiter storage config
app.config['RATELIMIT_STORAGE_URL'] = cfg.RATELIMIT_STORAGE_URL

db.init_app(app)

# ── FLASK-LIMITER (Bug #11: Rate limiting) ─────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute"],
    storage_uri=cfg.RATELIMIT_STORAGE_URL
)

# ── FLASK-LOGIN ────────────────────────────────────────────
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login first"

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None

@login_manager.unauthorized_handler
def unauthorized():
    """Handle unauthorized access"""
    if request.path.startswith('/api/'):
        return jsonify({
            "status": "error",
            "code": "AUTH_REQUIRED",
            "message": "Authentication required"
        }), 401
    return redirect(url_for('login'))

# ── SOCKET.IO ──────────────────────────────────────────────
socketio = SocketIO(
    app,
    cors_allowed_origins="*",  # Dev wildcard allowance to prevent localhost/127.0.0.1 mismatches
    async_mode='threading',
    logger=False,
    engineio_logger=False
)

# Register Auth Blueprint
app.register_blueprint(auth_bp)

# ── AUDIT LOGGING ──────────────────────────────────────────
@app.before_request
def audit_request():
    """Log all authenticated API accesses for audit trail."""
    if request.path.startswith('/api/') and current_user.is_authenticated:
        try:
            event = f"API: {current_user.username} {request.method} {request.path}"
            log_entry = Log(event=event)
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.warning(f"Audit log failed: {e}")

# ── GLOBAL STATE ───────────────────────────────────────────
detection_engine: Optional[DetectionEngine] = None
camera_thread: Optional[threading.Thread] = None
camera_active: bool = False
camera_lock: threading.Lock = threading.Lock()
_engine_lock: threading.Lock = threading.Lock()   # Bug #17: thread-safe init

# Runtime settings (Bug #7: actual server-side config storage)
_runtime_settings: Dict[str, Any] = {
    'conf_threshold': cfg.YOLO_CONFIDENCE_THRESHOLD,
    'iou_threshold': cfg.YOLO_IOU_THRESHOLD,
    'model_version': cfg.YOLO_MODEL,
    'fps_limit': 15,
    'data_retention_days': 30,
    'audio_alerts': True,
    'threat_override': True,
}


def get_engine() -> DetectionEngine:
    """Get or initialize the YOLO detection engine. Thread-safe singleton."""
    global detection_engine
    # Bug #17: Use a lock to prevent race condition during double-initialization
    with _engine_lock:
        if detection_engine is None:
            try:
                detection_engine = DetectionEngine(model_name=_runtime_settings.get('model_version'))
                logger.info("Detection engine initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize detection engine: {e}")
                raise
    return detection_engine


def _ts_str(ts) -> str:
    """Convert a datetime or string timestamp to ISO string safely.
    Ensures that timezone information is preserved for client-side local conversion."""
    if ts is None:
        return ''
    if hasattr(ts, 'astimezone'):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).isoformat()
    if hasattr(ts, 'strftime'):
        return ts.strftime('%Y-%m-%d %H:%M:%S')
    return str(ts)


def _to_ist_str(dt, fmt='%Y-%m-%d %H:%M:%S') -> str:
    """Helper to convert database UTC datetime to local IST timezone string."""
    if not dt:
        return 'unknown'
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    return dt.astimezone(ist_tz).strftime(fmt)


def _ts_hour(ts) -> str:
    """Return the YYYY-MM-DD HH key for a timestamp. Bug #3/#26."""
    if ts is None:
        return '0000-00-00 00'
    if hasattr(ts, 'strftime'):
        return ts.strftime('%Y-%m-%d %H')
    return str(ts)[:13]


# ── AUTH ──────────────────────────────────────────────────

@app.route('/')
def index():
    """Root route - redirect to dashboard or login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET'])
def login():
    """Frontend HTML login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/register', methods=['GET'])
def register():
    """Frontend HTML register page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout_page():
    try:
        username = current_user.username
        try:
            log_entry = Log(event=f"Logout: {username}")
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.warning(f"Logout log failed: {e}")
        logout_user()
        logger.info(f"User logged out: {username}")
    except Exception as e:
        logger.error(f"Logout error: {e}")
    return redirect(url_for('login'))


# ── DASHBOARD ─────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page with real detection stats from DB.
    Bug #1: Now queries actual data instead of passing empty lists."""
    try:
        # Total detections
        total = db.session.query(func.count(Detection.id)).scalar() or 0

        # Threat level breakdown
        by_threat = db.session.query(
            Detection.threat_level,
            func.count(Detection.id).label('cnt')
        ).group_by(Detection.threat_level).all()

        # Last 15 detections — serialize timestamps to strings for template safety
        recent_dets = db.session.query(Detection).order_by(
            Detection.timestamp.desc()
        ).limit(15).all()
        detections = [
            {
                'id': d.id,
                'module_name': d.module_name,
                'object_detected': d.object_detected,
                'confidence': d.confidence,
                'threat_level': d.threat_level,
                'timestamp': _ts_str(d.timestamp),
            }
            for d in recent_dets
        ]

        # Last 10 logs
        recent_logs_q = db.session.query(Log).order_by(
            Log.timestamp.desc()
        ).limit(10).all()
        logs = [
            {'id': l.id, 'event': l.event, 'timestamp': _ts_str(l.timestamp)}
            for l in recent_logs_q
        ]

        return render_template(
            'dashboard.html',
            user=current_user.username,
            user_role=current_user.role,
            detections=detections,
            logs=logs,
            stats=by_threat,
            total=total,
            camera_active=camera_active
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('error.html', error="Dashboard load failed"), 500


# ── MODULES ───────────────────────────────────────────────

MODULES = {
    'border':     'Border Security Monitoring',
    'disaster':   'Disaster Detection',
    'railway':    'Railway Safety Detection',
    'smart_city': 'Smart City Surveillance',
    'mining':     'Mining Activity Detection',
    'forest':     'Forest Monitoring System',
}

@app.route('/module/<module_name>')
@login_required
def module_view(module_name):
    """Module-specific detection view"""
    if module_name not in MODULES:
        return redirect(url_for('dashboard'))

    try:
        detections_q = db.session.query(Detection).filter_by(
            module_name=module_name
        ).order_by(Detection.timestamp.desc()).limit(50).all()

        detections = [
            {
                'id': d.id,
                'module_name': d.module_name,
                'object_detected': d.object_detected,
                'confidence': d.confidence,
                'threat_level': d.threat_level,
                'timestamp': _ts_str(d.timestamp),
            }
            for d in detections_q
        ]

        return render_template(
            'module.html',
            user=current_user.username,
            module_name=module_name,
            module_title=MODULES[module_name],
            detections=detections,
            modules=MODULES,
            camera_active=camera_active
        )
    except Exception as e:
        logger.error(f"Module view error: {e}")
        return render_template('error.html', error="Module load failed"), 500


# ── SATELLITE PAGE ────────────────────────────────────────

@app.route('/satellite')
@login_required
def satellite():
    """Satellite monitoring page"""
    try:
        sat_dets_q = db.session.query(Detection).filter_by(
            module_name='satellite'
        ).order_by(Detection.timestamp.desc()).limit(30).all()

        sat_dets = [
            {
                'id': d.id,
                'object_detected': d.object_detected,
                'confidence': d.confidence,
                'threat_level': d.threat_level,
                'timestamp': _ts_str(d.timestamp),
            }
            for d in sat_dets_q
        ]

        return render_template(
            'satellite.html',
            user=current_user.username,
            detections=sat_dets,
            has_weather_key=bool(cfg.OPENWEATHER_API_KEY)
        )
    except Exception as e:
        logger.error(f"Satellite view error: {e}")
        return render_template('error.html', error="Satellite load failed"), 500


# ── ANALYTICS PAGE ────────────────────────────────────────

@app.route('/analytics')
@login_required
def analytics():
    """Analytics dashboard page"""
    try:
        date_from = request.args.get(
            'from',
            (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        )
        date_to = request.args.get('to', datetime.now().strftime('%Y-%m-%d'))

        return render_template(
            'analytics.html',
            user=current_user.username,
            date_from=date_from,
            date_to=date_to
        )
    except Exception as e:
        logger.error(f"Analytics view error: {e}")
        return render_template('error.html', error="Analytics load failed"), 500


# ── SETTINGS PAGE ─────────────────────────────────────────

@app.route('/settings')
@login_required
@admin_required
def settings():
    """Settings dashboard page"""
    try:
        return render_template(
            'settings.html',
            user=current_user.username,
            settings=_runtime_settings
        )
    except Exception as e:
        logger.error(f"Settings view error: {e}")
        return render_template('error.html', error="Settings load failed"), 500


# ── SETTINGS API (Bug #7: Real server-side settings persistence) ──

@app.route('/api/settings', methods=['GET'])
@login_required
@admin_required
def get_settings():
    """Get current system settings."""
    return jsonify({'success': True, 'settings': _runtime_settings})


@app.route('/api/settings', methods=['POST'])
@login_required
@admin_required
def update_settings():
    """
    Update runtime system settings.
    Bug #7: Replaces the fake localStorage-only saveSettings() with a real API.
    """
    global detection_engine
    payload = request.get_json(silent=True) or {}

    allowed_keys = {
        'conf_threshold', 'iou_threshold', 'fps_limit',
        'data_retention_days', 'audio_alerts', 'threat_override', 'model_version'
    }

    updated = {}
    for key, value in payload.items():
        if key not in allowed_keys:
            continue
        try:
            if key == 'conf_threshold':
                value = max(0.1, min(float(value), 0.99))
            elif key == 'iou_threshold':
                value = max(0.1, min(float(value), 0.99))
            elif key == 'fps_limit':
                value = max(1, min(int(value), 60))
            elif key == 'data_retention_days':
                value = max(1, min(int(value), 365))
            elif key in ('audio_alerts', 'threat_override'):
                value = bool(value)
            _runtime_settings[key] = value
            updated[key] = value
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid setting value for {key}: {e}")

    # Reload model if version changed
    if 'model_version' in updated:
        with _engine_lock:
            detection_engine = None  # Force re-init on next request
        logger.info(f"Model version changed to {updated['model_version']} — engine reset")

    # Log settings change
    try:
        log_entry = Log(event=f"Settings updated by {current_user.username}: {list(updated.keys())}")
        db.session.add(log_entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return jsonify({'success': True, 'updated': updated, 'settings': _runtime_settings})


# ── ANALYTICS API ─────────────────────────────────────────

@app.route('/api/analytics')
@login_required
def api_analytics():
    """API endpoint for analytics data with date filter support.
    Bug #8: date params are now properly consumed from query string."""
    try:
        date_from = request.args.get(
            'from', (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        )
        date_to = request.args.get('to', datetime.now().strftime('%Y-%m-%d'))

        # Safely parse start date
        try:
            y, m, d = map(int, date_from.split('-'))
            dt_from = datetime(y, m, d, 0, 0, 0)
        except Exception:
            dt_from = datetime.now() - timedelta(days=7)

        # Safely parse end date
        try:
            y, m, d = map(int, date_to.split('-'))
            dt_to = datetime(y, m, d, 23, 59, 59, 999999)
        except Exception:
            dt_to = datetime.now()

        detections = db.session.query(Detection).filter(
            Detection.timestamp >= dt_from,
            Detection.timestamp <= dt_to
        ).order_by(Detection.timestamp.desc()).all()

        # Serialize for compute functions — timestamps become strings
        dets_data = [
            {
                'id': d.id,
                'module_name': d.module_name,
                'object_detected': d.object_detected,
                'confidence': d.confidence,
                'threat_level': d.threat_level,
                'timestamp': d.timestamp,   # Keep as datetime for compute functions
            }
            for d in detections
        ]

        data = {
            'success': True,
            'trends':     compute_trends(dets_data),
            'threats':    compute_threats(dets_data),
            'modules':    compute_modules(dets_data),
            'confidence': compute_confidence(dets_data),
            'metrics':    compute_metrics(dets_data),
            'detections': [
                {
                    'id': d['id'],
                    'module_name': d['module_name'],
                    'object_detected': d['object_detected'],
                    'confidence': d['confidence'],
                    'threat_level': d['threat_level'],
                    'timestamp': _ts_str(d['timestamp']),
                }
                for d in dets_data[:50]
            ]
        }

        return jsonify(data)

    except Exception as e:
        logger.error(f"Analytics API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ai/copilot', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def ai_copilot():
    """
    Vajra Copilot API.
    Uses RAG (Retrieval-Augmented Generation) on recent database detections and logs.
    """
    payload = request.get_json(silent=True) or {}
    user_query = payload.get('message', '').strip()
    
    if not user_query:
        return jsonify({'error': 'Message query is required'}), 400

    try:
        # 1. Fetch data context from SQLite
        # Last 50 detections
        detections = db.session.query(Detection).order_by(Detection.timestamp.desc()).limit(50).all()
        # Last 20 system activity logs
        logs = db.session.query(Log).order_by(Log.timestamp.desc()).limit(20).all()

        # 2. Check if Groq API key is configured
        api_key = cfg.GROQ_API_KEY
        
        # Format the context data in local IST timezone for LLM consumption
        det_lines = []
        for d in detections:
            ts_str = _to_ist_str(d.timestamp)
            det_lines.append(f"- [{ts_str}] module: {d.module_name} | object: {d.object_detected} | conf: {d.confidence*100:.1f}% | threat: {d.threat_level}")
        
        log_lines = []
        for l in logs:
            ts_str = _to_ist_str(l.timestamp)
            log_lines.append(f"- [{ts_str}] event: {l.event}")

        context_detections = "\n".join(det_lines) if det_lines else "No recent detections found."
        context_logs = "\n".join(log_lines) if log_lines else "No recent system logs."

        if not api_key:
            # Local fallback RAG generator
            response_text = _run_local_rag_fallback(user_query, detections, logs)
            return jsonify({
                'success': True,
                'message': response_text,
                'provider': 'local_fallback'
            })

        # 3. Call Llama via Groq API
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        system_prompt = (
            "You are Vajra Copilot, a multi-domain situational awareness assistant. You have read-only access to the system logs and detections. "
            "Below is the current state of the database logs. Use ONLY this context to answer the user's question. "
            "Be professional, concise, direct, and security-focused. Format your response in markdown. "
            "If the user asks a general question or greeting, you can reply politely but keep the focus on security. "
            "If the information is not in the logs, state that clearly.\n\n"
            f"=== SURVEILLANCE DETECTIONS CONTEXT (LAST 50) ===\n{context_detections}\n\n"
            f"=== SYSTEM LOGS CONTEXT (LAST 20) ===\n{context_logs}"
        )

        groq_payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_query}
            ],
            "temperature": 0.2,
            "max_tokens": 1024
        }

        # Make the request to Groq API
        resp = req_lib.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers=headers,
            json=groq_payload,
            timeout=10
        )
        
        if resp.status_code == 200:
            result = resp.json()
            answer = result['choices'][0]['message']['content']
            return jsonify({
                'success': True,
                'message': answer,
                'provider': 'groq'
            })
        else:
            logger.warning(f"Groq API error (status {resp.status_code}): {resp.text}")
            # If Groq fails, use fallback
            fallback_answer = _run_local_rag_fallback(user_query, detections, logs)
            return jsonify({
                'success': True,
                'message': f"*(Groq API error {resp.status_code}. Loaded Local Vajra Copilot engine fallback)*\n\n{fallback_answer}",
                'provider': 'local_fallback'
            })

    except Exception as e:
        logger.error(f"Vajra Copilot error: {e}")
        return jsonify({'error': str(e)}), 500


def _run_local_rag_fallback(query: str, detections, logs) -> str:
    """
    Local rule-based pattern matching and log analyzer.
    Serves as a robust out-of-the-box local fallback for RAG queries.
    """
    q = query.lower()
    
    # 1. Summarize recent threats
    if any(k in q for k in ('threat', 'critical', 'alert', 'severity')):
        high = [d for d in detections if d.threat_level in ('HIGH', 'CRITICAL')]
        med = [d for d in detections if d.threat_level == 'MEDIUM']
        low = [d for d in detections if d.threat_level == 'LOW']
        
        response = [
            "### 🛡️ Vajra Copilot Threat Summary (Local Engine)",
            f"Analyzed the last **{len(detections)}** live database detections:",
            f"- **High Threats:** {len(high)} events",
            f"- **Medium Threats:** {len(med)} events",
            f"- **Low Threats:** {len(low)} events",
            ""
        ]
        
        if high:
            response.append("#### ⚠️ Active High Threat Items:")
            seen = set()
            for h in high[:5]:
                key = (h.module_name, h.object_detected)
                if key not in seen:
                    seen.add(key)
                    ts = _to_ist_str(h.timestamp, '%H:%M:%S')
                    response.append(f"- **{h.object_detected.upper()}** detected in *{h.module_name}* at {ts} (Confidence: {h.confidence*100:.1f}%)")
        else:
            response.append("✅ **No High Threat events detected in the current buffer.**")
            
        response.append("\n**Recommendations:** Maintain normal platform monitoring. Monitor the active channels.")
        return "\n".join(response)

    # 2. Module specific query
    for mod in ('border', 'disaster', 'railway', 'smart_city', 'mining', 'forest', 'satellite'):
        if mod in q or mod.replace('_', ' ') in q:
            mod_dets = [d for d in detections if d.module_name == mod]
            high_count = sum(1 for d in mod_dets if d.threat_level in ('HIGH', 'CRITICAL'))
            
            response = [
                f"### 📡 Module Report: {mod.replace('_', ' ').upper()} (Local Engine)",
                f"Found **{len(mod_dets)}** records for module `{mod}` in the active database context.",
            ]
            if mod_dets:
                objects = {}
                for d in mod_dets:
                    objects[d.object_detected] = objects.get(d.object_detected, 0) + 1
                obj_str = ", ".join([f"{k} (x{v})" for k, v in objects.items()])
                response.append(f"- **Objects detected:** {obj_str}")
                response.append(f"- **High Threat alerts:** {high_count} events")
                
                if mod == 'satellite':
                    response.append("\n*Note: Satellite module requires coordinates search inputs to pull live ESRI tiles.*")
            else:
                response.append(f"No recent activity logged for module `{mod}`.")
            return "\n".join(response)

    # 3. System activity / logs query
    if any(k in q for k in ('log', 'activity', 'system', 'event', 'audit')):
        response = [
            "### 📋 System Activity Audit (Local Engine)",
            f"Displaying last **{min(5, len(logs))}** security audit events:",
        ]
        for l in logs[:5]:
            ts = _to_ist_str(l.timestamp)
            response.append(f"- `[{ts}]` {l.event}")
        return "\n".join(response)

    # 4. Greeting / general AI helper
    if any(k in q for k in ('hi', 'hello', 'hey', 'who are you', 'help')):
        return (
            "### 👋 Hello! I am Vajra Copilot, your situational awareness assistant.\n\n"
            "I have real-time access to the **VAJRA-X database** logs. You can ask me questions like:\n"
            "- *'Summarize recent threats'* to see high severity alerts.\n"
            "- *'Show system logs'* to check recent operator actions.\n"
            "- *'What happened in border monitoring?'* for module-specific queries.\n\n"
            "*(Groq API connection is currently running in local verification mode. Define a `GROQ_API_KEY` in the environment to unlock full Llama chat reasoning)*"
        )

    # Default fallback response
    high_count = sum(1 for d in detections if d.threat_level in ('HIGH', 'CRITICAL'))
    return (
        f"### 🤖 Vajra Copilot\n\n"
        f"I received your query: *\"{query}\"*\n\n"
        f"**Database Snapshot Context:**\n"
        f"- **Active Detections:** {len(detections)} entries\n"
        f"- **Unresolved High Threats:** {high_count} alerts\n"
        f"- **System Audit Logs:** {len(logs)} events\n\n"
        "Please specify if you want to know about **threats**, **system logs**, or a specific surveillance **module** (e.g. `border`, `smart_city`)."
    )


def compute_trends(detections) -> Dict[str, Any]:
    """Compute detection trends by hour.
    Bug #3/#26: Uses _ts_hour() to safely handle datetime objects."""
    trends_by_hour: Dict[str, int] = {}
    for det in detections:
        hour = _ts_hour(det['timestamp'])
        trends_by_hour[hour] = trends_by_hour.get(hour, 0) + 1

    sorted_hours = sorted(trends_by_hour.items())
    return {
        'labels': [h[0] for h in sorted_hours],   # Bug #26: full date+hour label
        'values': [h[1] for h in sorted_hours]
    }


def compute_threats(detections) -> Dict[str, int]:
    """Count threats by level."""
    threats = {'high': 0, 'medium': 0, 'low': 0}
    for det in detections:
        level = det.get('threat_level')
        if level is not None:
            level = level.lower()
            if level in threats:
                threats[level] += 1
    return threats


def compute_modules(detections) -> Dict[str, Any]:
    """Count detections by module."""
    modules: Dict[str, int] = {}
    for det in detections:
        mod = det.get('module_name', 'unknown')
        modules[mod] = modules.get(mod, 0) + 1

    sorted_mods = sorted(modules.items(), key=lambda x: x[1], reverse=True)
    return {
        'names':  [m[0] for m in sorted_mods],
        'counts': [m[1] for m in sorted_mods]
    }


def compute_confidence(detections) -> Dict[str, Any]:
    """Compute confidence score distribution."""
    ranges = {'60-70': 0, '70-80': 0, '80-90': 0, '90-95': 0, '>95': 0}
    for det in detections:
        try:
            conf = float(det['confidence'])
        except (TypeError, ValueError):
            continue
        if conf < 0.7:
            ranges['60-70'] += 1
        elif conf < 0.8:
            ranges['70-80'] += 1
        elif conf < 0.9:
            ranges['80-90'] += 1
        elif conf < 0.95:
            ranges['90-95'] += 1
        else:
            ranges['>95'] += 1

    return {'distribution': list(ranges.values())}


def compute_metrics(detections) -> Dict[str, Any]:
    """Compute key metrics.
    Bug #3: Uses _ts_hour() for safe datetime handling.
    Bug #27: avgAccuracy now returns float with 1 decimal place."""
    if not detections:
        return {
            'peakHour':      '-',
            'avgPerHour':    0,
            'alertRate':     0,
            'topModule':     '-',
            'avgAccuracy':   '0.0%',
            'highConfidence': 0,
            'lowConfidence':  0
        }

    # Peak hour — Bug #3: safe datetime handling
    hours: Dict[str, int] = {}
    for det in detections:
        hour = _ts_hour(det['timestamp'])
        hours[hour] = hours.get(hour, 0) + 1
    peak_hour = max(hours, key=hours.get)
    # Show just HH:00 in UI but keep full key for accuracy
    peak_hour_str = peak_hour.split(' ')[1] + ':00' if ' ' in peak_hour else peak_hour

    # Average detections per hour
    unique_hours = len(hours)
    avg_per_hour = round(len(detections) / max(1, unique_hours), 2)

    # Alert rate (HIGH threats)
    alerts = sum(1 for d in detections if (d.get('threat_level') or '') in ('HIGH', 'CRITICAL'))
    alert_rate = round((alerts / len(detections) * 100) if detections else 0, 1)

    # Top module
    modules_cnt: Dict[str, int] = {}
    for det in detections:
        mod = det.get('module_name', 'unknown')
        modules_cnt[mod] = modules_cnt.get(mod, 0) + 1
    top_mod = max(modules_cnt, key=modules_cnt.get) if modules_cnt else '-'

    # Bug #27: Average accuracy as float (was int, truncating decimals)
    confidences = [float(d['confidence']) for d in detections if d.get('confidence') is not None]
    avg_accuracy = round(sum(confidences) / len(confidences) * 100, 1) if confidences else 0.0

    # Confidence band counts as percentages
    high_conf = sum(1 for d in detections if float(d.get('confidence', 0)) > 0.85)
    high_conf_pct = round((high_conf / len(detections) * 100) if detections else 0, 1)

    low_conf = sum(1 for d in detections if float(d.get('confidence', 1)) < 0.60)
    low_conf_pct = round((low_conf / len(detections) * 100) if detections else 0, 1)

    return {
        'peakHour':       peak_hour_str,
        'avgPerHour':     avg_per_hour,
        'alertRate':      alert_rate,
        'topModule':      top_mod,
        'avgAccuracy':    f"{avg_accuracy}%",
        'highConfidence': high_conf_pct,
        'lowConfidence':  low_conf_pct
    }


# ── FILE UPLOAD ───────────────────────────────────────────

ALLOWED_IMAGE = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
ALLOWED_VIDEO = {'mp4', 'avi', 'mov', 'mkv', 'webm'}

@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("20 per minute")     # Bug #11: Rate limit uploads
def upload_file():
    """Handle file upload and run detection"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file   = request.files['file']
    module = request.form.get('module', 'smart_city')
    if module not in MODULES and module != 'satellite':
        module = 'smart_city'

    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'error': 'Invalid filename'}), 400

    ext      = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    is_image = ext in ALLOWED_IMAGE
    is_video = ext in ALLOWED_VIDEO

    if not is_image and not is_video:
        return jsonify({'error': 'Invalid file type. Allowed: jpg/png/mp4/avi etc.'}), 400

    os.makedirs(app.config['UPLOAD_FOLDER'],    exist_ok=True)
    os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)

    ts_str    = datetime.now().strftime('%Y%m%d_%H%M%S')
    save_name = f"{ts_str}_{filename}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], save_name)

    try:
        file.save(save_path)
    except Exception as e:
        logger.error(f"File save failed: {e}")
        return jsonify({'error': f'Could not save file: {e}'}), 500

    try:
        engine = get_engine()
        if is_image:
            result = engine.process_image(
                save_path,
                module,
                conf_thresh=_runtime_settings.get('conf_threshold'),
                iou_thresh=_runtime_settings.get('iou_threshold')
            )
            if result['success']:
                proc_name = f"proc_{save_name}"
                proc_path = os.path.join(app.config['PROCESSED_FOLDER'], proc_name)
                cv2.imwrite(proc_path, result['annotated_frame'])
                _store_detections(result['detections'], module,
                                  f'Image processed: {filename}')
                socketio.emit('detection_update', {
                    'detections': result['detections'], 'module': module, 'source': 'upload'
                })
                return jsonify({
                    'success': True, 'detections': result['detections'],
                    'processed_url': f'/static/processed/{proc_name}',
                    'count': len(result['detections'])
                })
            return jsonify({'error': result.get('error', 'Processing failed')}), 500

        else:  # video
            result = engine.process_video_file(
                save_path,
                module,
                conf_thresh=_runtime_settings.get('conf_threshold'),
                iou_thresh=_runtime_settings.get('iou_threshold')
            )
            if result['success']:
                _store_detections(result['detections'], module,
                                  f"Video processed: {filename} "
                                  f"({result['total_detections']} hits)")
                socketio.emit('detection_update', {
                    'detections': result['detections'], 'module': module, 'source': 'video'
                })
                return jsonify({
                    'success':          True,
                    'detections':       result['detections'],
                    'total_detections': result['total_detections'],
                    'frames_processed': result['frames_processed']
                })
            return jsonify({'error': result.get('error', 'Video failed')}), 500

    except Exception as e:
        logger.error(f'Upload error: {e}')
        return jsonify({'error': str(e)}), 500


def _store_detections(detections, module, log_event):
    """Helper: write detections + log to DB using SQLAlchemy"""
    try:
        for d in detections:
            detection = Detection(
                module_name=module,
                object_detected=d['label'],
                confidence=float(d['confidence']),
                threat_level=d['threat_level'],
            )
            db.session.add(detection)

        log_entry = Log(event=log_event)
        db.session.add(log_entry)
        db.session.commit()
        logger.info(f"Stored {len(detections)} detections for {module}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error storing detections: {e}")


# ── SATELLITE API ─────────────────────────────────────────

def _lat_lon_to_tile(lat, lon, zoom):
    """Convert lat/lon degrees to tile x,y at given zoom."""
    n = 2 ** zoom
    x = int((lon + 180) / 360 * n)
    y = int((1 - math.asinh(math.tan(math.radians(lat))) / math.pi) / 2 * n)
    return x, y


def _fetch_satellite_tiles(lat, lon, zoom=17, grid=3):
    """Fetch NxN satellite tiles from ESRI World Imagery and stitch them."""
    from PIL import Image
    cx, cy  = _lat_lon_to_tile(lat, lon, zoom)
    offset  = grid // 2
    tile_px = 256
    canvas  = Image.new('RGB', (tile_px * grid, tile_px * grid), (20, 20, 20))
    s = req_lib.Session()
    s.headers.update({'User-Agent': 'VajraX/2.0 Situational-Awareness'})

    for row in range(grid):
        for col in range(grid):
            tx, ty = cx + col - offset, cy + row - offset
            url = (
                f"https://server.arcgisonline.com/ArcGIS/rest/services/"
                f"World_Imagery/MapServer/tile/{zoom}/{ty}/{tx}"
            )
            try:
                resp = s.get(url, timeout=12)
                if resp.status_code == 200:
                    tile = Image.open(io.BytesIO(resp.content)).convert('RGB')
                    canvas.paste(tile, (col * tile_px, row * tile_px))
            except Exception as e:
                logger.warning(f'Tile {tx},{ty} failed: {e}')
    return canvas


@app.route('/api/geocode')
@login_required
@limiter.limit("30 per minute")     # Bug #11: Rate limit geocode
def geocode():
    """Convert a city/address query to lat/lon via Nominatim (free, no key).
    Bug #28: Input sanitized before forwarding to external API."""
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'error': 'No query provided'}), 400

    # Bug #28: Sanitize — allow letters, digits, spaces, commas, dots, hyphens only
    q_sanitized = re.sub(r'[^\w\s,.\-]', '', q)[:200]
    if not q_sanitized:
        return jsonify({'error': 'Invalid query characters'}), 400

    try:
        resp = req_lib.get(
            'https://nominatim.openstreetmap.org/search',
            params={'q': q_sanitized, 'format': 'json', 'limit': 1},
            headers={'User-Agent': 'VajraX/2.0'},
            timeout=10
        )
        data = resp.json()
        if not data:
            return jsonify({'error': f'Location not found: {q_sanitized}'}), 404
        loc = data[0]
        return jsonify({
            'lat':          float(loc['lat']),
            'lon':          float(loc['lon']),
            'display_name': loc['display_name']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/satellite/analyze', methods=['POST'])
@login_required
@limiter.limit("10 per minute")     # Bug #11: Rate limit satellite scan (heavy op)
def satellite_analyze():
    """Fetch real satellite tiles, run YOLO, return annotated image."""
    data   = request.get_json(silent=True) or {}
    lat    = data.get('lat')
    lon    = data.get('lon')
    zoom   = max(14, min(int(data.get('zoom', 17)), 19))
    grid   = max(2,  min(int(data.get('grid', 3)),  5))
    module = data.get('module', 'smart_city')

    if lat is None or lon is None:
        return jsonify({'error': 'lat and lon are required'}), 400

    try:
        lat, lon = float(lat), float(lon)
        if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            return jsonify({'error': 'Invalid coordinates'}), 400

        pil_img = _fetch_satellite_tiles(lat, lon, zoom=zoom, grid=grid)
        frame   = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

        engine = get_engine()
        result = engine.process_satellite_frame(
            frame,
            module,
            conf_thresh=_runtime_settings.get('conf_threshold'),
            iou_thresh=_runtime_settings.get('iou_threshold')
        )

        if not result['success']:
            return jsonify({'error': result.get('error', 'Analysis failed')}), 500

        _, buf = cv2.imencode('.jpg', result['annotated_frame'],
                              [cv2.IMWRITE_JPEG_QUALITY, 88])
        annotated_b64 = 'data:image/jpeg;base64,' + base64.b64encode(buf).decode()

        _, buf2 = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 82])
        original_b64 = 'data:image/jpeg;base64,' + base64.b64encode(buf2).decode()

        try:
            for d in result['detections']:
                detection = Detection(
                    module_name='satellite',
                    object_detected=d['label'],
                    confidence=float(d['confidence']),
                    threat_level=d['threat_level'],
                )
                db.session.add(detection)

            if result['detections']:
                log_entry = Log(
                    event=f"Satellite scan ({lat:.4f},{lon:.4f}) z{zoom}: "
                          f"{len(result['detections'])} detections"
                )
                db.session.add(log_entry)

            db.session.commit()
        except Exception as db_error:
            db.session.rollback()
            logger.error(f"Error storing satellite detections: {db_error}")

        socketio.emit('detection_update', {
            'detections': result['detections'],
            'module':     'satellite',
            'source':     'satellite'
        })

        return jsonify({
            'success':    True,
            'annotated':  annotated_b64,
            'original':   original_b64,
            'detections': result['detections'],
            'zoom':       zoom,
            'grid':       grid,
            'resolution': f'{256*grid}×{256*grid}px',
        })

    except Exception as e:
        logger.error(f'Satellite analyze error: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/weather')
@login_required
@limiter.limit("30 per minute")
def get_weather():
    """Fetch current weather from OpenWeatherMap (free tier, API key required)."""
    lat     = request.args.get('lat')
    lon     = request.args.get('lon')
    
    # Check backend config first
    api_key = (cfg.OPENWEATHER_API_KEY or '').strip()
    if not api_key:
        api_key = request.args.get('key', '').strip()

    if not lat or not lon:
        return jsonify({'error': 'lat and lon required'}), 400

    if not api_key:
        return jsonify({'no_key': True,
                        'message': 'Enter your free OpenWeatherMap API key'}), 200
    try:
        resp = req_lib.get(
            'https://api.openweathermap.org/data/2.5/weather',
            params={'lat': lat, 'lon': lon, 'appid': api_key, 'units': 'metric'},
            timeout=10
        )
        d = resp.json()
        if resp.status_code != 200:
            return jsonify({'error': d.get('message', 'Weather API error')}), 400

        vis_km    = d.get('visibility', 0) / 1000
        wind_spd  = d['wind']['speed']
        clouds    = d['clouds']['all']
        condition = d['weather'][0]['main']

        if vis_km < 1 or condition in ('Fog', 'Mist', 'Smoke', 'Haze'):
            surv_level = 'POOR'
        elif vis_km < 5 or clouds > 80 or wind_spd > 15:
            surv_level = 'MODERATE'
        else:
            surv_level = 'GOOD'

        return jsonify({
            'success':       True,
            'city':          d.get('name', 'Unknown'),
            'country':       d.get('sys', {}).get('country', ''),
            'temp':          round(d['main']['temp'], 1),
            'feels_like':    round(d['main']['feels_like'], 1),
            'humidity':      d['main']['humidity'],
            'pressure':      d['main']['pressure'],
            'visibility_km': round(vis_km, 1),
            'wind_speed':    wind_spd,
            'wind_deg':      d['wind'].get('deg', 0),
            'condition':     condition,
            'description':   d['weather'][0]['description'].title(),
            'icon':          d['weather'][0]['icon'],
            'clouds':        clouds,
            'sunrise':       d['sys']['sunrise'],
            'sunset':        d['sys']['sunset'],
            'surv_level':    surv_level,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── CAMERA STREAM ──────────────────────────────────────────

def _thread_db_insert(module_name, detections):
    """Write detections from background camera thread using SQLAlchemy app context.
    Bug #5: Replaced raw sqlite3.connect() with proper SQLAlchemy session."""
    try:
        with app.app_context():
            for d in detections:
                detection = Detection(
                    module_name=module_name,
                    object_detected=d['label'],
                    confidence=d['confidence'],
                    threat_level=d['threat_level'],
                )
                db.session.add(detection)
            db.session.commit()
    except Exception as e:
        logger.error(f'Thread DB write error: {e}')
        try:
            db.session.rollback()
        except Exception:
            pass


def camera_stream_worker(module_name):
    global camera_active
    cap = None
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            socketio.emit('camera_error', {
                'message': 'No camera found on server. Use Browser Webcam mode.'
            })
            camera_active = False
            return

        cap.set(cv2.CAP_PROP_FRAME_WIDTH,  640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        cap.set(cv2.CAP_PROP_FPS, _runtime_settings.get('fps_limit', 15))

        engine    = get_engine()
        frame_cnt = 0
        socketio.emit('camera_status', {'status': 'active', 'message': 'Camera started'})

        while camera_active:
            ret, frame = cap.read()
            if not ret or frame is None:
                time.sleep(0.1)
                continue

            frame_cnt += 1
            if frame_cnt % 3 == 0:
                result = engine.process_frame(
                    frame,
                    module_name,
                    conf_thresh=_runtime_settings.get('conf_threshold'),
                    iou_thresh=_runtime_settings.get('iou_threshold')
                )
                if result['success']:
                    _, buf = cv2.imencode('.jpg', result['annotated_frame'],
                                         [cv2.IMWRITE_JPEG_QUALITY, 70])
                    socketio.emit('live_frame', {
                        'frame':      base64.b64encode(buf).decode(),
                        'detections': result['detections'],
                        'module':     module_name,
                    })
                    if result['detections']:
                        _thread_db_insert(module_name, result['detections'])
                        socketio.emit('detection_update', {
                            'detections': result['detections'],
                            'module':     module_name,
                            'source':     'live_camera',
                        })
            time.sleep(0.05)

    except Exception as e:
        logger.error(f'Camera thread error: {e}')
        socketio.emit('camera_error', {'message': str(e)})
    finally:
        if cap:
            cap.release()
        camera_active = False
        socketio.emit('camera_status', {'status': 'stopped', 'message': 'Camera stopped'})


@socketio.on('start_camera')
def handle_start_camera(data):
    global camera_thread, camera_active
    if not current_user.is_authenticated:
        emit('error', {'message': 'Unauthorized'})
        return
    module = (data or {}).get('module', 'smart_city')
    with camera_lock:
        if not camera_active:
            camera_active = True
            camera_thread = threading.Thread(
                target=camera_stream_worker, args=(module,), daemon=True
            )
            camera_thread.start()
            emit('camera_status', {'status': 'starting', 'message': 'Initializing…'})
        else:
            emit('camera_status', {'status': 'already_active',
                                   'message': 'Camera already running'})


@socketio.on('stop_camera')
def handle_stop_camera():
    global camera_active
    camera_active = False
    emit('camera_status', {'status': 'stopped', 'message': 'Camera stopped'})


@socketio.on('connect')
def handle_connect():
    """Handle Socket.IO client connection"""
    try:
        if current_user.is_authenticated:
            emit('system_status', {
                'status':  'connected',
                'camera':  camera_active,
                'message': f'Connected as {current_user.username}'
            })
            try:
                log_entry = Log(event=f'Socket connected: {current_user.username}')
                db.session.add(log_entry)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to log socket connection: {e}")
                db.session.rollback()
        else:
            emit('system_status', {
                'status':  'unauthorized',
                'message': 'Authentication required'
            })
    except Exception as e:
        logger.error(f"Socket connection error: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle Socket.IO client disconnection"""
    try:
        if current_user.is_authenticated:
            logger.info(f"Socket disconnected: {current_user.username}")
    except Exception as e:
        logger.debug(f"Disconnect handler error: {e}")


# ── WEBCAM FRAME API ──────────────────────────────────────

@app.route('/api/process_webcam_frame', methods=['POST'])
@login_required
@limiter.limit("120 per minute")    # Bug #11: Rate limit webcam frames
def process_webcam_frame():
    """Process webcam frame and run detection"""
    data = request.get_json(silent=True)
    if not data or 'frame' not in data:
        return jsonify({'error': 'No frame data'}), 400

    module = data.get('module', 'smart_city')
    try:
        raw = data['frame']
        if ',' in raw:
            raw = raw.split(',', 1)[1]
        arr   = np.frombuffer(base64.b64decode(raw), np.uint8)
        frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if frame is None:
            return jsonify({'error': 'Cannot decode frame'}), 400

        engine = get_engine()
        result = engine.process_frame(
            frame,
            module,
            conf_thresh=_runtime_settings.get('conf_threshold'),
            iou_thresh=_runtime_settings.get('iou_threshold')
        )
        if not result['success']:
            return jsonify({'error': result.get('error')}), 500

        _, buf = cv2.imencode('.jpg', result['annotated_frame'],
                              [cv2.IMWRITE_JPEG_QUALITY, 75])
        processed = 'data:image/jpeg;base64,' + base64.b64encode(buf).decode()

        if result['detections']:
            try:
                for d in result['detections']:
                    detection = Detection(
                        module_name=module,
                        object_detected=d['label'],
                        confidence=float(d['confidence']),
                        threat_level=d['threat_level'],
                    )
                    db.session.add(detection)
                db.session.commit()

                socketio.emit('detection_update', {
                    'detections': result['detections'],
                    'module':     module,
                    'source':     'webcam'
                })
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error storing detections: {e}")

        return jsonify({
            'success':         True,
            'processed_frame': processed,
            'detections':      result['detections']
        })

    except Exception as e:
        logger.error(f'Webcam frame error: {e}')
        return jsonify({'error': str(e)}), 500


# ── JSON API ──────────────────────────────────────────────

@app.route('/api/detections')
@login_required
def api_detections():
    """Get detections with optional module filter and pagination.
    Bug #15: Added proper pagination with page/limit params."""
    try:
        module = request.args.get('module')
        limit  = min(int(request.args.get('limit', 50)), 500)
        page   = max(int(request.args.get('page', 1)), 1)
        offset = (page - 1) * limit

        query = db.session.query(Detection).order_by(Detection.timestamp.desc())

        if module:
            query = query.filter_by(module_name=module)

        total   = query.count()
        records = query.offset(offset).limit(limit).all()

        return jsonify({
            'data': [
                {
                    'id':             d.id,
                    'module_name':    d.module_name,
                    'object_detected': d.object_detected,
                    'confidence':     d.confidence,
                    'threat_level':   d.threat_level,
                    'timestamp':      _ts_str(d.timestamp),
                }
                for d in records
            ],
            'pagination': {
                'page':  page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit,
            }
        })
    except Exception as e:
        logger.error(f"API detections error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
@login_required
def api_stats():
    """Get detection statistics with optional module filter."""
    try:
        module = request.args.get('module')
        
        total_query = db.session.query(func.count(Detection.id))
        by_threat_query = db.session.query(
            Detection.threat_level,
            func.count(Detection.id).label('count')
        ).group_by(Detection.threat_level)
        
        if module:
            total_query = total_query.filter(Detection.module_name == module)
            by_threat_query = by_threat_query.filter(Detection.module_name == module)
            
        total = total_query.scalar() or 0
        by_threat = by_threat_query.all()

        by_module = db.session.query(
            Detection.module_name,
            func.count(Detection.id).label('count')
        ).group_by(Detection.module_name).all()

        # Bug #2: Return by_threat as a DICT (matching JS: s.by_threat['HIGH'])
        by_threat_norm = {}
        for t, c in by_threat:
            if t is not None:
                k = str(t).upper()
                by_threat_norm[k] = by_threat_norm.get(k, 0) + c

        return jsonify({
            'total':     total,
            'by_module': {m: c for m, c in by_module},
            'by_threat': by_threat_norm,
        })
    except Exception as e:
        logger.error(f"API stats error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs')
@login_required
@admin_required
def api_logs():
    """Get recent activity logs — Bug #15: paginated."""
    try:
        limit  = min(int(request.args.get('limit', 100)), 500)
        page   = max(int(request.args.get('page', 1)), 1)
        offset = (page - 1) * limit

        query  = db.session.query(Log).order_by(Log.timestamp.desc())
        total  = query.count()
        logs   = query.offset(offset).limit(limit).all()

        return jsonify({
            'data': [
                {
                    'id':        log.id,
                    'event':     log.event,
                    'timestamp': _ts_str(log.timestamp),
                }
                for log in logs
            ],
            'pagination': {'page': page, 'limit': limit, 'total': total}
        })
    except Exception as e:
        logger.error(f"API logs error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/clear_detections', methods=['POST'])
@login_required
@admin_required
@limiter.limit("5 per minute")
def clear_detections():
    """Clear detections (admin only)"""
    try:
        payload = request.get_json(silent=True) or {}
        module  = payload.get('module')

        if module:
            count = db.session.query(Detection).filter_by(module_name=module).delete()
        else:
            count = db.session.query(Detection).delete()

        db.session.commit()
        logger.info(f"Cleared {count} detections for module: {module or 'all'}")

        return jsonify({'success': True, 'message': f'Cleared {count} detections'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error clearing detections: {e}")
        return jsonify({'error': str(e)}), 500


# ── FILE CLEANUP (Bug #16) ────────────────────────────────

def _cleanup_old_files():
    """Delete uploaded/processed files older than data_retention_days setting.
    Bug #16: Prevents disk from filling up over time."""
    retention_days = _runtime_settings.get('data_retention_days', 30)
    cutoff = datetime.now() - timedelta(days=retention_days)
    removed = 0

    for folder in [app.config['UPLOAD_FOLDER'], app.config['PROCESSED_FOLDER']]:
        for filepath in Path(folder).iterdir():
            try:
                if filepath.is_file():
                    mtime = datetime.fromtimestamp(filepath.stat().st_mtime)
                    if mtime < cutoff:
                        filepath.unlink()
                        removed += 1
            except Exception as e:
                logger.warning(f"Cleanup error for {filepath}: {e}")

    if removed:
        logger.info(f"File cleanup: removed {removed} old files (>{retention_days}d)")
    return removed


@app.route('/api/cleanup', methods=['POST'])
@login_required
@admin_required
@limiter.limit("3 per hour")
def trigger_cleanup():
    """Manually trigger file cleanup. Bug #16."""
    try:
        removed = _cleanup_old_files()
        return jsonify({'success': True, 'files_removed': removed})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── HEALTH ENDPOINT (Bug #24) ─────────────────────────────

@app.route('/health')
def health():
    """Health check endpoint for load balancers and monitoring.
    Bug #24: Required for enterprise/cloud deployment."""
    try:
        # Quick DB connectivity check
        db.session.execute(db.text('SELECT 1'))
        db_status = 'ok'
    except Exception as e:
        db_status = f'error: {e}'

    engine_status = 'loaded' if (detection_engine and detection_engine.model_loaded) else 'not_loaded'

    status_code = 200 if db_status == 'ok' else 503
    return jsonify({
        'status':         'ok' if status_code == 200 else 'degraded',
        'version':        '2.0.0',
        'database':       db_status,
        'ai_engine':      engine_status,
        'camera_active':  camera_active,
        'timestamp':      datetime.now(timezone.utc).isoformat(),
    }), status_code


# ── ERROR HANDLERS ────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found', 'code': 404}), 404
    return render_template('error.html', error='Page not found', code=404), 404


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error', 'code': 500}), 500
    return render_template('error.html', error='Internal server error', code=500), 500


@app.errorhandler(413)
def too_large(e):
    logger.warning("File upload exceeded maximum size")
    return jsonify({'error': 'File too large. Max 100 MB.'}), 413


@app.errorhandler(429)
def rate_limited(e):
    """Handle rate limit exceeded — Bug #11."""
    return jsonify({
        'error':   'Rate limit exceeded. Please slow down.',
        'code':    429,
        'retry_after': str(e.description)
    }), 429


# ── STARTUP ───────────────────────────────────────────────

def create_app() -> Flask:
    """Initialize Flask application with database and directories"""
    try:
        Path(cfg.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
        Path(cfg.PROCESSED_FOLDER).mkdir(parents=True, exist_ok=True)
        Path(BASE_DIR / 'database').mkdir(parents=True, exist_ok=True)
        Path(BASE_DIR / 'logs').mkdir(parents=True, exist_ok=True)

        logger.info("Created necessary directories")

        with app.app_context():
            db.create_all()
            logger.info("SQLAlchemy tables initialized")
            
            # Seeding default admin user if none exist
            from werkzeug.security import generate_password_hash
            if not db.session.query(User).first():
                default_admin = User(
                    username=cfg.ADMIN_USERNAME,
                    password_hash=generate_password_hash(cfg.ADMIN_PASSWORD),
                    role='admin',
                    email=f"{cfg.ADMIN_USERNAME}@vajrax.local"
                )
                db.session.add(default_admin)
                db.session.commit()
                logger.info(f"Default admin user '{cfg.ADMIN_USERNAME}' seeded successfully")

        logger.info(f"VAJRA-X Core v2.0 initialized in {cfg.FLASK_ENV} mode")
        return app
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise


@app.teardown_appcontext
def teardown_db(exception):
    """Release the SQLAlchemy connection pool slot at the end of every request context.
    Uses db.session.remove() — the canonical SQLAlchemy teardown pattern.
    Legacy close_db() fully removed (Bug #5 cleanup)."""
    db.session.remove()


if __name__ == '__main__':
    app_instance = create_app()
    logger.info(f"Starting server on {cfg.HOST}:{cfg.PORT}")
    socketio.run(
        app_instance,
        host=cfg.HOST,
        port=cfg.PORT,
        debug=cfg.DEBUG,
        use_reloader=cfg.DEBUG,
        allow_unsafe_werkzeug=True
    )
