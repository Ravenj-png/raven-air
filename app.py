import os, re, jwt, logging, smtplib, requests, bleach, json, threading, time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, field_validator
from tenacity import retry, stop_after_attempt, wait_exponential
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import redis

# Load env vars
load_dotenv()

# --- MONITORING & LOGGING ---
SENTRY_DSN = os.environ.get('SENTRY_DSN')
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, integrations=[FlaskIntegration()], traces_sample_rate=1.0)

class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "exception": self.formatException(record.exc_info) if record.exc_info else None
        })

handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# --- APP CONFIG ---
app = Flask(__name__)

SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY: raise RuntimeError("SECRET_KEY missing")
app.config['SECRET_KEY'] = SECRET_KEY

# Database
DB_URL = os.environ.get('DATABASE_URL')
if not DB_URL: raise RuntimeError("DATABASE_URL missing")
if DB_URL.startswith('postgres://'): DB_URL = DB_URL.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- REDIS WITH FALLBACK ---
REDIS_URL = os.environ.get('REDIS_URL')
r = None
USE_REDIS = False

if REDIS_URL:
    try:
        r = redis.from_url(REDIS_URL, decode_responses=True, ssl_cert_reqs=None)
        r.ping()
        USE_REDIS = True
        logger.info("✅ Redis Connected: Using Redis for Rate Limits & CSRF")
    except Exception as e:
        logger.warning(f"⚠️ Redis Connection Failed: {e}. Falling back to Memory/Local Storage.")
        USE_REDIS = False
else:
    logger.warning("⚠️ REDIS_URL not found. Falling back to Memory/Local Storage.")

# Security
CSP_POLICY = {
    'default-src': "'self'",
    'script-src': ["'self'", "https://www.google.com", "https://www.gstatic.com", "https://unpkg.com"],
    'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    'img-src': ["'self'", "https:"],
    'connect-src': ["'self'", "https://api.openweathermap.org", "https://api.x.ai"], 
}
Talisman(app, force_https=True, content_security_policy=CSP_POLICY)

FRONTEND_URL = 'https://ravenj-png.github.io'
BACKEND_URL = 'https://raven-air.onrender.com'
ALLOWED_ORIGINS = [FRONTEND_URL, BACKEND_URL]

CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS, "methods": ["GET", "POST"], "allow_headers": ["Content-Type", "X-CSRF-Token", "Authorization"], "supports_credentials": True}})

# Rate Limiter with Fallback
limiter_storage = REDIS_URL if USE_REDIS else "memory://"
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=limiter_storage,
    strategy="fixed-window"
)

# Database & Migrations
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class ContactSubmission(db.Model):
    __tablename__ = 'contact_submissions'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    service_type = db.Column(db.String(50))
    message = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45))

# Validation Models
class ContactSchema(BaseModel):
    name: str
    email: EmailStr
    phone: str | None = None
    service_type: str | None = "General Inquiry"
    message: str
    recaptcha_token: str

    @field_validator('name')
    def name_not_empty(cls, v):
        if len(v) < 2: raise ValueError('Name too short')
        return v

    @field_validator('message')
    def message_valid(cls, v):
        if len(v) < 10 or len(v) > 5000: raise ValueError('Message length invalid')
        return v

class ChatSchema(BaseModel):
    message: str
    history: list = []

# Utils
def sanitize_input(text):
    if not text: return ""
    return bleach.clean(text, tags=[], strip=True)[:5000]

def verify_recaptcha(token):
    if not token: return False
    try:
        secret = os.environ.get('RECAPTCHA_SECRET_KEY')
        r_req = requests.post('https://www.google.com/recaptcha/api/siteverify', data={'secret': secret, 'response': token}, timeout=5)
        res = r_req.json()
        return res.get('success', False) and res.get('score', 0) >= 0.5
    except Exception as e:
        logger.error(f"Recaptcha error: {e}")
        return False

# Background Tasks
def send_email_async(sub):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"New Contact - {sub.service_type}"
        msg['From'] = os.environ.get('SMTP_USER')
        msg['To'] = os.environ.get('ADMIN_EMAIL')
        msg['Reply-To'] = sub.email
        msg.attach(MIMEText(f"Name: {sub.name}\nEmail: {sub.email}\nMessage:\n{sub.message}", 'plain'))
        
        smtp_user = os.environ.get('SMTP_USER')
        smtp_pass = os.environ.get('SMTP_PASS')
        if smtp_user and smtp_pass:
            with smtplib.SMTP('smtp.gmail.com', 587) as s:
                s.starttls()
                s.login(smtp_user, smtp_pass)
                s.send_message(msg)
        logger.info(f"Email sent to {sub.email}")
    except Exception as e:
        logger.error(f"Async Email Error: {e}")

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def call_grok_api(messages):
    api_key = os.environ.get('GROK_API_KEY')
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    payload = {"messages": messages, "model": "grok-beta", "stream": False, "temperature": 0.7}
    response = requests.post("https://api.x.ai/v1/chat/completions", headers=headers, json=payload, timeout=10)
    response.raise_for_status()
    return response.json()['choices'][0]['message']['content']

# Auth Decorators
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        expected_key = os.environ.get('API_CHAT_KEY')
        if expected_key and auth_header != f"Bearer {expected_key}":
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_csrf_fallback(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token:
            return jsonify({'error': 'CSRF Token Missing'}), 403
        
        if USE_REDIS:
            try:
                stored_token = r.get(f"csrf:{csrf_token}")
                if not stored_token:
                    return jsonify({'error': 'Invalid or Expired CSRF Token (Redis)'}), 403
            except Exception as e:
                logger.warning(f"Redis CSRF check failed, falling back to JWT validation: {e}")
                try:
                    jwt.decode(csrf_token, app.config['SECRET_KEY'], algorithms=['HS256'])
                except Exception:
                    return jsonify({'error': 'Invalid CSRF Token (JWT Fallback)'}), 403
        else:
            try:
                jwt.decode(csrf_token, app.config['SECRET_KEY'], algorithms=['HS256'])
            except Exception:
                return jsonify({'error': 'Invalid CSRF Token'}), 403
            
        return f(*args, **kwargs)
    return decorated_function

# Routes (/api/v1/)

@app.route('/api/v1/health')
def health():
    return jsonify({
        'status': 'healthy', 
        'redis_connected': USE_REDIS,
        'rate_limit_storage': limiter_storage
    })

@app.route('/api/v1/csrf-token', methods=['GET'])
def get_csrf_token():
    token = jwt.encode({'exp': datetime.utcnow() + timedelta(hours=1), 'jti': str(time.time())}, app.config['SECRET_KEY'], algorithm='HS256')
    
    if USE_REDIS:
        try:
            r.setex(f"csrf:{token}", 3600, "valid")
        except Exception as e:
            logger.warning(f"Failed to store CSRF in Redis: {e}")
    
    resp = make_response(jsonify({'csrf_token': token}))
    return resp

@app.route('/api/v1/weather', methods=['GET'])
@limiter.limit("30 per minute")
def get_weather():
    city = request.args.get('city', 'Kampala')
    api_key = os.environ.get('WEATHER_API_KEY')
    if not api_key: return jsonify({'temp': 26, 'desc': 'Cloudy'}), 200
    try:
        url = f"https://api.openweathermap.org/data/2.5/weather?q={city},UG&appid={api_key}&units=metric"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        return jsonify({'temp': round(data['main']['temp']), 'desc': data['weather'][0]['description'].title(), 'humidity': data['main']['humidity']})
    except Exception as e:
        logger.error(f"Weather API Error: {e}")
        return jsonify({'error': 'Weather service unavailable'}), 503

@app.route('/api/v1/chat', methods=['POST'])
@require_api_key
@limiter.limit("20 per minute")
def chat_endpoint():
    try:
        data = ChatSchema(**request.get_json())
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    system_prompt = [{"role": "system", "content": "You are Air System Coolers AI Assistant. Be professional."}]
    history = [{"role": m['role'], "content": m['content']} for m in data.history[-5:]]
    messages = system_prompt + history + [{"role": "user", "content": data.message}]

    try:
        reply = call_grok_api(messages)
        return jsonify({'reply': reply})
    except Exception as e:
        logger.error(f"Grok API Error: {e}")
        return jsonify({'error': 'AI Service Temporarily Unavailable'}), 503

@app.route('/api/v1/contact', methods=['POST'])
@require_csrf_fallback
@limiter.limit("5 per minute")
def submit_contact():
    try:
        data = ContactSchema(**request.get_json())
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    if not verify_recaptcha(data.recaptcha_token):
        return jsonify({'error': 'Security Check Failed'}), 403

    sub = ContactSubmission(
        name=sanitize_input(data.name),
        email=data.email.lower(),
        phone=sanitize_input(data.phone),
        service_type=sanitize_input(data.service_type),
        message=sanitize_input(data.message),
        ip_address=request.remote_addr
    )
    
    db.session.add(sub)
    db.session.commit()
    
    thread = threading.Thread(target=send_email_async, args=(sub,))
    thread.start()
    
    return jsonify({'success': True, 'reference': f"ASC-{sub.id}"}), 201

@app.route('/api/v1/counseling', methods=['POST'])
@require_csrf_fallback
@limiter.limit("3 per minute")
def submit_counseling():
    data = request.get_json()
    if not data: return jsonify({'error': 'No data'}), 400
    if not data.get('email') or not data.get('message'): return jsonify({'error': 'Missing fields'}), 400
        
    sub = ContactSubmission(
        name=sanitize_input(data.get('name')),
        email=data.get('email').lower(),
        phone=sanitize_input(data.get('phone')),
        service_type=f"Consultation: {data.get('service', 'General')}",
        message=sanitize_input(data.get('message')),
        ip_address=request.remote_addr
    )
    
    db.session.add(sub)
    db.session.commit()
    
    thread = threading.Thread(target=send_email_async, args=(sub,))
    thread.start()
    
    return jsonify({'success': True, 'reference': f"CNS-{sub.id}"}), 201

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled Exception: {e}")
    return jsonify({'error': 'Internal Server Error'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
