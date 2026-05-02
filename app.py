import os, re, jwt, logging, smtplib, requests, bleach, json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-me')

# Database Configuration: Uses Render's DATABASE_URL if available, else SQLite
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith('postgres://'):
    # Fix for newer SQLAlchemy versions requiring postgresql:// instead of postgres://
    db_url = db_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///airsystem.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security Headers (CSP) - Strict for Production
CSP_POLICY = {
    'default-src': "'self'",
    'script-src': ["'self'", "https://www.google.com", "https://www.gstatic.com", "https://unpkg.com"],
    'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    'img-src': ["'self'", "https:", ""],
    'connect-src': ["'self'", "https://api.openweathermap.org", "https://api.x.ai"],
}
# Force HTTPS in production
Talisman(app, force_https=True, content_security_policy=CSP_POLICY)

# CORS - Strictly allow only your GitHub Pages Frontend and Render Backend
FRONTEND_URL = 'https://ravenj-png.github.io'
BACKEND_URL = 'https://raven-air.onrender.com'

ALLOWED_ORIGINS = [FRONTEND_URL, BACKEND_URL, 'http://localhost:5500'] # Localhost for testing

CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS, "methods": ["GET", "POST"], "allow_headers": ["Content-Type", "X-CSRF-Token"], "supports_credentials": True}})

# Rate Limiting
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Database
db = SQLAlchemy(app)

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

# Security Utils
def sanitize_input(text):
    if not text: return ""
    return bleach.clean(text, tags=[], strip=True)[:5000]

def verify_recaptcha(token, action='submit'):
    if not token or token == 'demo-token':
        return True, 0.9
    try:
        secret = os.environ.get('RECAPTCHA_SECRET_KEY')
        if not secret: return True, 0.9
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data={'secret': secret, 'response': token}, timeout=5)
        res = r.json()
        return res.get('success', False) and res.get('score', 0) >= 0.5, res.get('score', 0)
    except:
        return True, 0.9

def send_email(sub):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"New Contact - {sub.service_type or 'General'}"
        msg['From'] = os.environ.get('SMTP_USER')
        msg['To'] = os.environ.get('ADMIN_EMAIL', msg['From'])
        msg['Reply-To'] = sub.email

        text = f"Name: {sub.name}\nEmail: {sub.email}\nPhone: {sub.phone or 'N/A'}\nService: {sub.service_type}\n\nMessage:\n{sub.message}"
        html = f"<h2>New Contact</h2><p><strong>Name:</strong> {sub.name}<br><strong>Email:</strong> {sub.email}<br><strong>Message:</strong><br>{sub.message}</p>"

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        smtp_user = os.environ.get('SMTP_USER')
        smtp_pass = os.environ.get('SMTP_PASS')

        if smtp_user and smtp_pass:
            with smtplib.SMTP('smtp.gmail.com', 587) as s:
                s.starttls()
                s.login(smtp_user, smtp_pass)
                s.send_message(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

# ========== AI CHATBOT LOGIC (GROK) ==========
def get_grok_response(user_message, chat_history=[]):
    api_key = os.environ.get('GROK_API_KEY')
    if not api_key:
        return "I'm currently in maintenance mode. Please call +256 741 333 544."

    system_prompt = """
    You are the AI Assistant for 'Air System Coolers Limited' in Kampala, Uganda.
    
    COMPANY INFO:
    - Services: Industrial & Domestic HVAC, Fire Fighting Systems (NFPA Certified), Electrical Power Systems, Ventilation.
    - Certifications: ISO 9001, ASHRAE, AMCA, CFPS.
    - Experience: 25+ Years.
    - Location: Kampala, Uganda (Industrial Area).
    - Contact: +256 741 333 544, info@airsystemcoolers.com.
    - Emergency: 24/7 Support available.
    
    INSTRUCTIONS:
    - Be professional, concise, and helpful.
    - If asked about prices, say 'Prices vary by project size. Please request a quote via our contact form or WhatsApp.'
    - If asked about technical specs, provide general industry standards (ASHRAE/NFPA).
    - Always encourage them to contact the engineering team for specific quotes.
    - Keep responses under 3 sentences unless explaining a technical concept.
    """

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    messages = [{"role": "system", "content": system_prompt}]
    # Add history context (last 5 messages to save tokens)
    messages.extend(chat_history[-5:])
    messages.append({"role": "user", "content": user_message})

    payload = {
        "messages": messages,
        "model": "grok-beta",
        "stream": False,
        "temperature": 0.7
    }

    try:
        response = requests.post("https://api.x.ai/v1/chat/completions", headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data['choices'][0]['message']['content']
    except Exception as e:
        print(f"Grok API Error: {e}")
        return "I'm having trouble connecting to my brain right now. Please call us directly at +256 741 333 544."

# ========== API ROUTES ==========

@app.route('/')
def home():
    return jsonify({'status': 'Air System Coolers API', 'version': '1.0'})

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = jwt.encode({'exp': datetime.utcnow() + timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
    resp = make_response(jsonify({'csrf_token': token}))
    # Secure cookie settings for production
    resp.set_cookie('csrf_token', token, httponly=False, secure=True, samesite='None')
    return resp

@app.route('/api/weather', methods=['GET'])
@limiter.limit("30 per minute")
def get_weather():
    city = request.args.get('city', 'Kampala')
    api_key = os.environ.get('WEATHER_API_KEY')

    if not api_key:
        return jsonify({'temp': 26, 'desc': 'Partly Cloudy', 'humidity': 65})

    try:
        url = f"http://api.openweathermap.org/data/2.5/weather?q={city},UG&appid={api_key}&units=metric"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        return jsonify({
            'temp': round(data['main']['temp']),
            'desc': data['weather'][0]['description'].title(),
            'humidity': data['main']['humidity']
        })
    except:
        return jsonify({'temp': 25, 'desc': 'Weather data unavailable', 'humidity': 70})

@app.route('/api/chat', methods=['POST'])
@limiter.limit("20 per minute")
def chat_endpoint():
    data = request.get_json()
    user_message = data.get('message', '')
    history = data.get('history', [])

    if not user_message:
        return jsonify({'error': 'Message required'}), 400

    response_text = get_grok_response(user_message, history)

    return jsonify({'reply': response_text})

@app.route('/api/contact', methods=['POST'])
@limiter.limit("5 per minute")
def submit_contact():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Verify reCAPTCHA
    is_human, score = verify_recaptcha(data.get('recaptcha_token'))
    if not is_human:
        return jsonify({'error': 'Security verification failed'}), 403

    # Validate
    name = sanitize_input(data.get('name', ''))
    email = data.get('email', '').strip().lower()
    message = sanitize_input(data.get('message', ''))

    if not name or len(name) < 2:
        return jsonify({'error': 'Valid name required'}), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Valid email required'}), 400
    if not message or len(message) < 10:
        return jsonify({'error': 'Message must be at least 10 characters'}), 400

    # Save to database
    sub = ContactSubmission(
        name=name,
        email=email,
        phone=sanitize_input(data.get('phone', '')),
        service_type=sanitize_input(data.get('service_type', 'General Inquiry')),
        message=message,
        ip_address=request.remote_addr
    )
    db.session.add(sub)
    db.session.commit()

    # Send email
    send_email(sub)

    return jsonify({
        'success': True,
        'message': 'Thank you! We will contact you within 24 hours.',
        'reference': f"ASC-{sub.id}"
    }), 201

@app.route('/api/counseling', methods=['POST'])
@limiter.limit("3 per minute")
def submit_counseling():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    is_human, _ = verify_recaptcha(data.get('recaptcha_token'))
    if not is_human:
        return jsonify({'error': 'Security verification failed'}), 403

    name = sanitize_input(data.get('name', ''))
    email = data.get('email', '').strip().lower()
    message = sanitize_input(data.get('message', ''))

    if not name or len(name) < 2:
        return jsonify({'error': 'Valid name required'}), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Valid email required'}), 400

    sub = ContactSubmission(
        name=name,
        email=email,
        phone=sanitize_input(data.get('phone', '')),
        service_type=f"Consultation: {sanitize_input(data.get('service', 'General'))}",
        message=message,
        ip_address=request.remote_addr
    )
    db.session.add(sub)
    db.session.commit()

    send_email(sub)

    return jsonify({'success': True, 'message': 'Consultation request received!', 'reference': f"CNS-{sub.id}"}), 201

# Error handlers
@app.errorhandler(404)
def not_found(e): return jsonify({'error': 'Not found'}), 404
@app.errorhandler(429)
def rate_limit(e): return jsonify({'error': 'Too many requests. Please wait.'}), 429

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Get port from environment variable, default to 5000 if not found
    port = int(os.environ.get('PORT', 5000))

    # For production (Render), we usually use Gunicorn, but this fallback helps for debugging
    # Ensure host is 0.0.0.0 so it accepts external connections
    app.run(host='0.0.0.0', port=port, debug=False)
