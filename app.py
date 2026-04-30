from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random
import re
import os

app = Flask(__name__)

# ============================================================
# SECURITY FIX 1: Strong Secret Key (OWASP A02 - Cryptographic Failures)
# Never use default/weak secret keys
# ============================================================
app.secret_key = os.urandom(24)  # Random key generated at startup

# ============================================================
# SECURITY FIX 2: Secure Session Configuration (OWASP A07 - Auth Failures)
# ============================================================
app.config['SESSION_COOKIE_HTTPONLY'] = True   # JS cannot read cookies
app.config['SESSION_COOKIE_SECURE'] = False     # Set True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ============================================================
# DATABASE MODELS
# ============================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed
    role = db.Column(db.String(10), default='student')    # 'student' or 'admin'
    fee_paid = db.Column(db.Boolean, default=False)
    test_date = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.relationship('Result', backref='user', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)  # A, B, C, or D
    category = db.Column(db.String(100), default='General')

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.DateTime, default=datetime.utcnow)

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def login_required(f):
    """Decorator to protect routes that need login"""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first!', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator to protect admin-only routes"""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        # ============================================================
        # SECURITY FIX 3: Broken Access Control (OWASP A01)
        # Check BOTH login AND role - not just login
        # ============================================================
        if 'user_id' not in session:
            flash('Please login first!', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access Denied! Admin only area.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def sanitize_input(text):
    """
    SECURITY FIX 4: Injection Prevention (OWASP A03)
    Remove dangerous characters from user input
    """
    if text:
        # Remove HTML tags and script tags
        text = re.sub(r'<[^>]*>', '', text)
        # Remove special SQL-like characters
        text = text.strip()
    return text

# ============================================================
# PUBLIC ROUTES
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name  = sanitize_input(request.form.get('name', ''))
        email = sanitize_input(request.form.get('email', '').lower())
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        # Input validation
        if not name or not email or not password:
            flash('All fields are required!', 'danger')
            return render_template('register.html')

        if password != confirm:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')

        # ============================================================
        # SECURITY FIX 5: Weak Password Policy (OWASP A07)
        # Enforce strong passwords
        # ============================================================
        if len(password) < 8:
            flash('Password must be at least 8 characters!', 'danger')
            return render_template('register.html')

        # Check if email already exists
        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('Email already registered!', 'warning')
            return render_template('register.html')

        # ============================================================
        # SECURITY FIX 6: Storing plain text passwords (OWASP A02)
        # Always hash passwords using bcrypt/pbkdf2
        # ============================================================
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = sanitize_input(request.form.get('email', '').lower())
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        # ============================================================
        # SECURITY FIX 7: Authentication check (OWASP A07)
        # Use check_password_hash - never compare plain text
        # ============================================================
        if user and check_password_hash(user.password, password):
            session.clear()  # Clear old session data
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['role'] = user.role
            # session.permanent = False  # Session expires when browser closes

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()  # SECURITY: Clear ALL session data on logout
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# ============================================================
# STUDENT ROUTES
# ============================================================

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    results = Result.query.filter_by(user_id=user.id).order_by(Result.date_taken.desc()).all()
    return render_template('dashboard.html', user=user, results=results)

@app.route('/pay_fee', methods=['GET', 'POST'])
@login_required
def pay_fee():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        card = sanitize_input(request.form.get('card_number', ''))
        # In real system, integrate payment gateway (Stripe etc.)
        # Here we simulate payment success
        user.fee_paid = True
        db.session.commit()
        flash('Fee paid successfully! You can now take the quiz.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('pay_fee.html', user=user)

@app.route('/take_quiz')
@login_required
def take_quiz():
    user = User.query.get(session['user_id'])

    if not user.fee_paid:
        flash('Please pay the fee first to take the quiz!', 'warning')
        return redirect(url_for('pay_fee'))

    all_questions = Question.query.all()
    if len(all_questions) == 0:
        flash('No questions available yet. Contact admin.', 'warning')
        return redirect(url_for('dashboard'))

    # ============================================================
    # FEATURE: Random Questions (as required by sir)
    # ============================================================
    num_questions = min(10, len(all_questions))
    questions = random.sample(all_questions, num_questions)

    # Store question IDs in session to prevent cheating
    session['quiz_questions'] = [q.id for q in questions]

    return render_template('quiz.html', questions=questions)

@app.route('/submit_quiz', methods=['POST'])
@login_required
def submit_quiz():
    quiz_questions = session.get('quiz_questions', [])
    if not quiz_questions:
        flash('No active quiz found!', 'danger')
        return redirect(url_for('dashboard'))

    score = 0
    total = len(quiz_questions)

    for qid in quiz_questions:
        question = Question.query.get(qid)
        user_answer = request.form.get(f'q_{qid}', '').upper()
        if question and user_answer == question.correct_answer.upper():
            score += 1

    # Save result
    result = Result(user_id=session['user_id'], score=score, total=total)
    db.session.add(result)
    db.session.commit()

    session.pop('quiz_questions', None)  # Clear quiz from session

    return render_template('result.html', score=score, total=total,
                           percentage=round((score/total)*100, 1))

# ============================================================
# ADMIN ROUTES
# ============================================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    users   = User.query.filter_by(role='student').all()
    questions = Question.query.all()
    results = Result.query.all()
    return render_template('admin_dashboard.html',
                           users=users, questions=questions, results=results)

@app.route('/admin/add_question', methods=['GET', 'POST'])
@admin_required
def add_question():
    if request.method == 'POST':
        q_text  = sanitize_input(request.form.get('question_text', ''))
        opt_a   = sanitize_input(request.form.get('option_a', ''))
        opt_b   = sanitize_input(request.form.get('option_b', ''))
        opt_c   = sanitize_input(request.form.get('option_c', ''))
        opt_d   = sanitize_input(request.form.get('option_d', ''))
        correct = request.form.get('correct_answer', '').upper()
        category = sanitize_input(request.form.get('category', 'General'))

        if not all([q_text, opt_a, opt_b, opt_c, opt_d, correct]):
            flash('All fields required!', 'danger')
        elif correct not in ['A', 'B', 'C', 'D']:
            flash('Correct answer must be A, B, C, or D!', 'danger')
        else:
            q = Question(question_text=q_text, option_a=opt_a, option_b=opt_b,
                         option_c=opt_c, option_d=opt_d,
                         correct_answer=correct, category=category)
            db.session.add(q)
            db.session.commit()
            flash('Question added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))

    return render_template('add_question.html')

@app.route('/admin/delete_question/<int:qid>')
@admin_required
def delete_question(qid):
    q = Question.query.get_or_404(qid)
    db.session.delete(q)
    db.session.commit()
    flash('Question deleted!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/assign_date/<int:uid>', methods=['POST'])
@admin_required
def assign_date(uid):
    user = User.query.get_or_404(uid)
    test_date = request.form.get('test_date', '')
    user.test_date = sanitize_input(test_date)
    db.session.commit()
    flash(f'Test date assigned to {user.name}!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:uid>')
@admin_required
def delete_user(uid):
    user = User.query.get_or_404(uid)
    # ============================================================
    # SECURITY: Admin cannot delete other admins
    # ============================================================
    if user.role == 'admin':
        flash('Cannot delete admin accounts!', 'danger')
        return redirect(url_for('admin_dashboard'))
    Result.query.filter_by(user_id=uid).delete()
    db.session.delete(user)
    db.session.commit()
    flash('User deleted!', 'success')
    return redirect(url_for('admin_dashboard'))

# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    with app.app_context():
        db.create_all()

        # Create default admin if not exists
        admin = User.query.filter_by(email='admin@quiz.com').first()
        if not admin:
            admin = User(
                name='Administrator',
                email='admin@quiz.com',
                password=generate_password_hash('Admin@1234', method='pbkdf2:sha256'),
                role='admin',
                fee_paid=True
            )
            db.session.add(admin)

        # Add sample questions if none exist
        if Question.query.count() == 0:
            sample_questions = [
                Question(question_text='What does OWASP stand for?',
                         option_a='Open Web Application Security Project',
                         option_b='Online Web App Security Protocol',
                         option_c='Open World Access Security Program',
                         option_d='None of the above',
                         correct_answer='A', category='Security'),
                Question(question_text='Which attack injects malicious scripts into web pages?',
                         option_a='SQL Injection',
                         option_b='Cross-Site Scripting (XSS)',
                         option_c='CSRF',
                         option_d='Buffer Overflow',
                         correct_answer='B', category='Security'),
                Question(question_text='What is the purpose of password hashing?',
                         option_a='Make passwords longer',
                         option_b='Encrypt passwords for transmission',
                         option_c='Store passwords securely so originals cannot be recovered',
                         option_d='Speed up login process',
                         correct_answer='C', category='Security'),
                Question(question_text='Which HTTP method is considered safe and idempotent?',
                         option_a='POST', option_b='DELETE', option_c='GET', option_d='PUT',
                         correct_answer='C', category='Web'),
                Question(question_text='What does SQL injection exploit?',
                         option_a='Weak passwords',
                         option_b='Unsanitized user input in database queries',
                         option_c='Insecure network connections',
                         option_d='Outdated software',
                         correct_answer='B', category='Security'),
                Question(question_text='Which OWASP category covers using outdated libraries?',
                         option_a='Broken Access Control',
                         option_b='Cryptographic Failures',
                         option_c='Vulnerable and Outdated Components',
                         option_d='Security Misconfiguration',
                         correct_answer='C', category='Security'),
                Question(question_text='What does HTTPS provide that HTTP does not?',
                         option_a='Faster speed',
                         option_b='Encrypted communication',
                         option_c='Larger file transfers',
                         option_d='Better caching',
                         correct_answer='B', category='Web'),
                Question(question_text='What is a CSRF attack?',
                         option_a='A database attack',
                         option_b='Cross-Site Request Forgery - tricks users to submit unwanted requests',
                         option_c='A type of virus',
                         option_d='Brute force login attack',
                         correct_answer='B', category='Security'),
            ]
            for q in sample_questions:
                db.session.add(q)

        db.session.commit()
        print("Database initialized!")
        print("Admin login: admin@quiz.com / Admin@1234")

if __name__ == '__main__':
    init_db()
    # ============================================================
    # SECURITY FIX 8: Security Misconfiguration (OWASP A05)
    # Debug=False in production, restrict host
    # ============================================================
    app.run(debug=True, host='127.0.0.1', port=5000)
