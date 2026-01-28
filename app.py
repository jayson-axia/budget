import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///budget.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Encryption setup
def get_encryption_key():
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key().decode()
    else:
        if len(key) != 44:
            key = base64.urlsafe_b64encode(key.encode().ljust(32)[:32]).decode()
    return key.encode() if isinstance(key, str) else key

cipher = Fernet(get_encryption_key())

def encrypt_data(data):
    if data:
        return cipher.encrypt(data.encode()).decode()
    return data

def decrypt_data(data):
    if data:
        try:
            return cipher.decrypt(data.encode()).decode()
        except:
            return data
    return data


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    incomes = db.relationship('Income', backref='user', lazy=True, cascade='all, delete-orphan')
    expenses = db.relationship('Expense', backref='user', lazy=True, cascade='all, delete-orphan')
    credentials = db.relationship('Credential', backref='user', lazy=True, cascade='all, delete-orphan')
    links = db.relationship('Link', backref='user', lazy=True, cascade='all, delete-orphan')


class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(200))
    password_encrypted = db.Column(db.Text)
    url = db.Column(db.String(500))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_encrypted = encrypt_data(password)

    def get_password(self):
        return decrypt_data(self.password_encrypted)


class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(50))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Only allow registration if no users exist (single user app)
    if User.query.count() > 0:
        flash('Registration is closed. This is a single-user app.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        if password != confirm:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return render_template('register.html')

        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Account created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Get summary data
    total_income = db.session.query(db.func.sum(Income.amount)).filter_by(user_id=current_user.id).scalar() or 0
    total_expenses = db.session.query(db.func.sum(Expense.amount)).filter_by(user_id=current_user.id).scalar() or 0
    balance = total_income - total_expenses

    recent_income = Income.query.filter_by(user_id=current_user.id).order_by(Income.date.desc()).limit(5).all()
    recent_expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).limit(5).all()

    return render_template('dashboard.html',
                         total_income=total_income,
                         total_expenses=total_expenses,
                         balance=balance,
                         recent_income=recent_income,
                         recent_expenses=recent_expenses)


# Income routes
@app.route('/income')
@login_required
def income_list():
    incomes = Income.query.filter_by(user_id=current_user.id).order_by(Income.date.desc()).all()
    total = sum(i.amount for i in incomes)
    return render_template('income.html', incomes=incomes, total=total)


@app.route('/income/add', methods=['GET', 'POST'])
@login_required
def income_add():
    if request.method == 'POST':
        income = Income(
            user_id=current_user.id,
            source=request.form.get('source'),
            amount=float(request.form.get('amount')),
            date=datetime.strptime(request.form.get('date'), '%Y-%m-%d').date(),
            notes=request.form.get('notes')
        )
        db.session.add(income)
        db.session.commit()
        flash('Income added successfully!', 'success')
        return redirect(url_for('income_list'))
    return render_template('income_form.html')


@app.route('/income/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def income_edit(id):
    income = Income.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        income.source = request.form.get('source')
        income.amount = float(request.form.get('amount'))
        income.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        income.notes = request.form.get('notes')
        db.session.commit()
        flash('Income updated successfully!', 'success')
        return redirect(url_for('income_list'))
    return render_template('income_form.html', income=income)


@app.route('/income/delete/<int:id>', methods=['POST'])
@login_required
def income_delete(id):
    income = Income.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(income)
    db.session.commit()
    flash('Income deleted successfully!', 'success')
    return redirect(url_for('income_list'))


# Expense routes
@app.route('/expenses')
@login_required
def expense_list():
    expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).all()
    total = sum(e.amount for e in expenses)
    return render_template('expenses.html', expenses=expenses, total=total)


@app.route('/expenses/add', methods=['GET', 'POST'])
@login_required
def expense_add():
    if request.method == 'POST':
        expense = Expense(
            user_id=current_user.id,
            category=request.form.get('category'),
            description=request.form.get('description'),
            amount=float(request.form.get('amount')),
            date=datetime.strptime(request.form.get('date'), '%Y-%m-%d').date(),
            notes=request.form.get('notes')
        )
        db.session.add(expense)
        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('expense_list'))
    return render_template('expense_form.html')


@app.route('/expenses/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def expense_edit(id):
    expense = Expense.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        expense.category = request.form.get('category')
        expense.description = request.form.get('description')
        expense.amount = float(request.form.get('amount'))
        expense.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        expense.notes = request.form.get('notes')
        db.session.commit()
        flash('Expense updated successfully!', 'success')
        return redirect(url_for('expense_list'))
    return render_template('expense_form.html', expense=expense)


@app.route('/expenses/delete/<int:id>', methods=['POST'])
@login_required
def expense_delete(id):
    expense = Expense.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted successfully!', 'success')
    return redirect(url_for('expense_list'))


# Credentials routes
@app.route('/credentials')
@login_required
def credential_list():
    credentials = Credential.query.filter_by(user_id=current_user.id).order_by(Credential.name).all()
    return render_template('credentials.html', credentials=credentials)


@app.route('/credentials/add', methods=['GET', 'POST'])
@login_required
def credential_add():
    if request.method == 'POST':
        credential = Credential(
            user_id=current_user.id,
            name=request.form.get('name'),
            username=request.form.get('username'),
            url=request.form.get('url'),
            notes=request.form.get('notes')
        )
        credential.set_password(request.form.get('password'))
        db.session.add(credential)
        db.session.commit()
        flash('Credential added successfully!', 'success')
        return redirect(url_for('credential_list'))
    return render_template('credential_form.html')


@app.route('/credentials/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def credential_edit(id):
    credential = Credential.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        credential.name = request.form.get('name')
        credential.username = request.form.get('username')
        credential.url = request.form.get('url')
        credential.notes = request.form.get('notes')
        password = request.form.get('password')
        if password:
            credential.set_password(password)
        db.session.commit()
        flash('Credential updated successfully!', 'success')
        return redirect(url_for('credential_list'))
    return render_template('credential_form.html', credential=credential)


@app.route('/credentials/delete/<int:id>', methods=['POST'])
@login_required
def credential_delete(id):
    credential = Credential.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(credential)
    db.session.commit()
    flash('Credential deleted successfully!', 'success')
    return redirect(url_for('credential_list'))


@app.route('/credentials/password/<int:id>')
@login_required
def credential_password(id):
    credential = Credential.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    return jsonify({'password': credential.get_password()})


# Links routes
@app.route('/links')
@login_required
def link_list():
    links = Link.query.filter_by(user_id=current_user.id).order_by(Link.category, Link.name).all()
    return render_template('links.html', links=links)


@app.route('/links/add', methods=['GET', 'POST'])
@login_required
def link_add():
    if request.method == 'POST':
        link = Link(
            user_id=current_user.id,
            name=request.form.get('name'),
            url=request.form.get('url'),
            category=request.form.get('category'),
            notes=request.form.get('notes')
        )
        db.session.add(link)
        db.session.commit()
        flash('Link added successfully!', 'success')
        return redirect(url_for('link_list'))
    return render_template('link_form.html')


@app.route('/links/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def link_edit(id):
    link = Link.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        link.name = request.form.get('name')
        link.url = request.form.get('url')
        link.category = request.form.get('category')
        link.notes = request.form.get('notes')
        db.session.commit()
        flash('Link updated successfully!', 'success')
        return redirect(url_for('link_list'))
    return render_template('link_form.html', link=link)


@app.route('/links/delete/<int:id>', methods=['POST'])
@login_required
def link_delete(id):
    link = Link.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(link)
    db.session.commit()
    flash('Link deleted successfully!', 'success')
    return redirect(url_for('link_list'))


# Initialize database
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
