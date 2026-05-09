import os
import jwt
import datetime
import dotenv
import yaml
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import threading
from datetime import datetime, timezone, timedelta
import json
import logging
import sys
import uuid
from pythonjsonlogger import jsonlogger
import time

SERVICE_START_TIME = datetime.now(timezone.utc)
REQUEST_STATS = {"2xx": 0, "4xx": 0, "5xx": 0, "other": 0}
STATS_LOCK = threading.Lock()

app = Flask(__name__)

# Загрузка конфигурации
def load_config():
    config_filename = f"config.yaml"
    try:
        with open(config_filename, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.error(f"Не найден файл конфигурации '{config_filename}', приложение не может быть запущено")
        raise FileNotFoundError(f"config file {config_filename} missing")
    except yaml.YAMLError as e:
        logging.error(f"Ошибка парсировки YAML: {e}")
        raise e

config = load_config()
app.config.update(config)
dotenv.load_dotenv("./.env")
key = os.getenv("SECRET_KEY")
uri = os.getenv("SQLALCHEMY_DATABASE_URI")

if not key:
    raise ValueError("no secret key provided")
if not uri:
    raise ValueError("no database URI provided")

app.config["SECRET_KEY"] = key
app.config["SQLALCHEMY_DATABASE_URI"] = uri

class RequestFormatter(jsonlogger.JsonFormatter):
    """Добавляет контекст запроса в каждый лог"""
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record['timestamp'] = datetime.now(timezone.utc).isoformat()
        log_record['level'] = record.levelname
        log_record['service'] = "auth-service"
        log_record['version'] = app.config.get('version', 'unknown')
        # Добавляем request_id из g (если установлен в before_request)
        if hasattr(g, 'request_id'):
            log_record['request_id'] = g.request_id
        # Добавляем пользовательский контекст, если есть
        if hasattr(g, 'current_user') and g.current_user:
            log_record['user_id'] = getattr(g.current_user, 'id', None)
            log_record['user_email'] = getattr(g.current_user, 'email', None)

# Настройка логгера
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(RequestFormatter(
    '%(timestamp)s %(level)s %(service)s %(request_id)s %(message)s'
))
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)
logger.propagate = False  # Чтобы не дублировать логи в root-логгер

db = SQLAlchemy(app)
CORS(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Integer, default=2)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat()
        }

# Инициализация БД и создание админа при первом запуске
with app.app_context():
    db.create_all()
    # Проверяем, есть ли пользователи. Если нет - создаем админа по умолчанию
    if not User.query.first():
        admin = User(
            email="admin@example.com",
            password_hash=generate_password_hash("admin_password"),
            role=2,
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print("[INFO] Admin user created: admin@example.com / admin_password")
        print(f"[INFO] Database created at: {app.config['SQLALCHEMY_DATABASE_URI']}")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user or not current_user.is_active:
                return jsonify({"message": "User not found or inactive"}), 401
            g.current_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(g, 'current_user') or g.current_user.role != 2:
            return jsonify({"message": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

@app.after_request
def track_response(response):
    """Подсчёт обработанных запросов по кодам ответов"""
    with STATS_LOCK:
        status = response.status_code
        if 200 <= status < 300:
            REQUEST_STATS["2xx"] += 1
        elif 400 <= status < 500:
            REQUEST_STATS["4xx"] += 1
        elif 500 <= status < 600:
            REQUEST_STATS["5xx"] += 1
        else:
            REQUEST_STATS["other"] += 1
    return response

@app.before_request
def before_request():
    """Генерирует request_id и логирует начало запроса"""
    g.request_id = str(uuid.uuid4())
    g.start_time = time.time()  # для расчёта duration

    logger.info("request_started", extra={
        "method": request.method,
        "path": request.path,
        "remote_addr": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', '')[:100]  # обрезаем, чтобы не засорять
    })

@app.after_request
def after_request(response):
    """Логирует завершение запроса с метриками"""
    duration = time.time() - getattr(g, 'start_time', time.time())

    log_data = {
        "method": request.method,
        "path": request.path,
        "status_code": response.status_code,
        "duration_ms": round(duration * 1000, 2),
        "response_size": response.content_length or 0
    }

    if response.status_code >= 400:
        # Логируем тело ошибки (но не успешные ответы и не авторизацию)
        log_data["response_sample"] = response.get_data(as_text=True)[:200]

    logger.info("request_completed", extra=log_data)
    return response

@app.route('/api/auth/healthcheck', methods=['GET'])
def healthcheck():
    return jsonify({"message": "all ok", "version": app.config['VERSION']})

@app.route('/api/auth/stats', methods=['GET'])
def stats():
    """Service metrics for monitoring and healthcheck"""
    now = datetime.now(timezone.utc)
    uptime = (now - SERVICE_START_TIME).total_seconds()

    with STATS_LOCK:
        stats_copy = dict(REQUEST_STATS)

    return jsonify({
        "service": "auth-service",
        "version": app.config.get('VERSION', app.config.get('service_version', 'unknown')),
        "start_time": SERVICE_START_TIME.isoformat(),
        "uptime_seconds": round(uptime, 2),
        "requests": stats_copy,
        "timestamp": now.isoformat()
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({"error_code": 400, "message": "Email and password are required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error_code": 409, "message": "User already exists"}), 409

    new_user = User(email=email, password_hash=generate_password_hash(password), role='user')
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "ok", "user_id": new_user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error_code": 500, "message": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password) and user.is_active:
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"message": "ok", "access_token": token}), 200

    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_me():
    user = g.current_user
    return jsonify({
        "message": "ok",
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat()
    }), 200

@app.route('/api/auth/users', methods=['GET'])
@token_required
@admin_required
def list_users():
    users = User.query.all()
    return jsonify({"message": "ok", "users": [u.to_dict() for u in users]}), 200

@app.route('/api/auth/users/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(user_id):
    current_user = g.current_user
    if user_id == current_user.id:
        return jsonify({"message": "Admin cannot delete themselves"}), 403
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({"message": "User not found"}), 404
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=app.config["debug_mode"])
