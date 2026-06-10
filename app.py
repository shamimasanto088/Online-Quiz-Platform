import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Secret key for encrypting sessions
app.config['SECRET_KEY'] = 'cybersecurity_quiz_secret_1337_key'
# SQL Database setup (creates quiz.db directly in the project folder)
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'quiz.db')

# Ensure the database folder exists automatically
os.makedirs(os.path.dirname(db_path), exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Rate Limiter setup to prevent brute-force attacks
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per minute"],
    storage_uri="memory://"
)

# --- DATABASE MODELS (SQL TABLES) ---

# User model for storing accounts
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    scores = db.relationship('Score', backref='user', lazy=True)

# Quiz Categories (e.g. Kali Basics, Web Hacking)
class QuizCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    difficulty = db.Column(db.String(20), default='Medium')
    questions = db.relationship('Question', backref='category', lazy=True)
    scores = db.relationship('Score', backref='category', lazy=True)

# Individual questions mapping to categories
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('quiz_category.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False) # 'A', 'B', 'C', or 'D'
    points = db.Column(db.Integer, default=10)

# Saved quiz results score history
class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('quiz_category.id'), nullable=False)
    score_value = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- SECURITY HEADERS ENFORCEMENT ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "frame-ancestors 'none';"
    )
    return response

# --- AUTHENTICATION HELPER ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get(user_id)

def login_required(view):
    import functools
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Access Denied! Please login first.', 'danger')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

# --- APPLICATION ROUTES ---

@app.route('/')
def home():
    if g.user:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not username or not password:
            flash('All fields are required!', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match!', 'danger')
        elif User.query.filter_by(username=username).first() is not None:
            flash(f'User {username} is already registered!', 'danger')
        else:
            hashed_pwd = generate_password_hash(password)
            new_user = User(username=username, password=hashed_pwd)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user is None or not check_password_hash(user.password, password):
            flash('Invalid username or password!', 'danger')
        else:
            session.clear()
            session['user_id'] = user.id
            flash(f'Secure session established. Welcome {user.username}.', 'success')
            return redirect(url_for('dashboard'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Terminal session closed.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    categories = QuizCategory.query.all()
    user_scores = Score.query.filter_by(user_id=g.user.id).all()
    
    total_quizzes = len(user_scores)
    avg_score = 0
    highest_score = 0
    rank = "Script Kiddie"
    
    if total_quizzes > 0:
        avg_score = round(sum([s.percentage for s in user_scores]) / total_quizzes, 1)
        highest_score = max([s.percentage for s in user_scores])
        
        if highest_score >= 90:
            rank = "Cyber Sentinel"
        elif highest_score >= 70:
            rank = "Ethical Hacker"
        elif highest_score >= 50:
            rank = "Junior Pen-Tester"
            
    recent_attempts = Score.query.filter_by(user_id=g.user.id).order_by(Score.completed_at.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                           categories=categories, 
                           total_quizzes=total_quizzes, 
                           avg_score=avg_score, 
                           highest_score=highest_score, 
                           rank=rank,
                           recent_attempts=recent_attempts)

@app.route('/quiz/<int:category_id>')
@login_required
def quiz(category_id):
    category = QuizCategory.query.get_or_404(category_id)
    questions = Question.query.filter_by(category_id=category_id).all()
    return render_template('quiz.html', category=category, questions=questions)

@app.route('/quiz/submit', methods=['POST'])
@login_required
def quiz_submit():
    category_id = request.form.get('category_id')
    questions = Question.query.filter_by(category_id=category_id).all()
    
    score_val = 0
    total_questions = len(questions)
    
    for q in questions:
        selected_option = request.form.get(f'question_{q.id}')
        if selected_option == q.correct_option:
            score_val += 1
            
    percentage = round((score_val / total_questions) * 100, 1) if total_questions > 0 else 0
    
    score_record = Score(
        user_id=g.user.id,
        category_id=category_id,
        score_value=score_val,
        total_questions=total_questions,
        percentage=percentage
    )
    db.session.add(score_record)
    db.session.commit()
    
    return redirect(url_for('results', score_id=score_record.id))

@app.route('/results/<int:score_id>')
@login_required
def results(score_id):
    score = Score.query.get_or_404(score_id)
    if score.user_id != g.user.id:
        return redirect(url_for('dashboard'))
        
    category = QuizCategory.query.get(score.category_id)
    questions = Question.query.filter_by(category_id=score.category_id).all()
    return render_template('results.html', score=score, category=category, questions=questions)

# --- DATABASE AUTO-SEEDER ---
def seed_data():
    if not QuizCategory.query.first():
        cat1 = QuizCategory(name="Kali Linux Basics", description="Basic commands, Linux permissions and package management.", difficulty="Easy")
        cat2 = QuizCategory(name="Web App Hacking", description="OWASP Top 10, SQL injection and Cross-Site Scripting (XSS).", difficulty="Medium")
        cat3 = QuizCategory(name="Network Scanning", description="Nmap flags, TCP SYN scanning and Wireshark filters.", difficulty="Hard")
        
        db.session.add_all([cat1, cat2, cat3])
        db.session.commit()

        # Questions for Easy Cat
        q1 = Question(category_id=cat1.id, question_text="Which command shows the current working directory?", option_a="dir", option_b="pwd", option_c="whoami", option_d="cd", correct_option="B")
        q2 = Question(category_id=cat1.id, question_text="What command sets a file to be executable in Linux?", option_a="chmod +x file", option_b="chown +x file", option_c="attrib +x file", option_d="run file", correct_option="A")
        
        # Questions for Medium Cat
        q3 = Question(category_id=cat2.id, question_text="Which character is commonly used to test for SQL injection?", option_a="Single quote (')", option_b="Double quote (\")", option_c="Semicolon (;)", option_d="Slash (/)", correct_option="A")
        q4 = Question(category_id=cat2.id, question_text="Which type of XSS stores the malicious payload permanently inside the database?", option_a="Reflected XSS", option_b="DOM XSS", option_c="Stored XSS", option_d="Self XSS", correct_option="C")
        
        # Questions for Hard Cat
        q5 = Question(category_id=cat3.id, question_text="Which Nmap flag is used for TCP SYN Scan?", option_a="-sT", option_b="-sS", option_c="-sU", option_d="-sA", correct_option="B")
        
        db.session.add_all([q1, q2, q3, q4, q5])
        db.session.commit()

# Create tables and auto seed
with app.app_context():
    db.create_all()
    seed_data()

if __name__ == '__main__':
    app.run(debug=True)