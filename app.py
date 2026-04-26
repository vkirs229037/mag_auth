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

app = Flask(__name__)

# Загрузка конфигурации
def load_config():
    env = os.getenv('ENVIRONMENT', 'dev').lower()
    config_filename = f"config.{env}.yaml"
    print(f"Загрузка конфига для окружения: {env} -> {config_filename}")

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
if not app.config["SECRET_KEY"]:
    dotenv.load_dotenv("./.env")
    key = os.getenv("SECRET_KEY")
    if not key:
        raise ValueError("no secret key provided")
    app.config["SECRET_KEY"] = key

db = SQLAlchemy(app)
CORS(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Integer, default=2)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
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

@app.route('/healthcheck', methods=['GET'])
def healthcheck():
    return jsonify({"message": "ok", "version": app.config['VERSION']})

@app.route('/api/register', methods=['POST'])
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

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password) and user.is_active:
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"message": "ok", "access_token": token}), 200

    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/me', methods=['GET'])
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

@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def list_users():
    users = User.query.all()
    return jsonify({"message": "ok", "users": [u.to_dict() for u in users]}), 200

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
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
