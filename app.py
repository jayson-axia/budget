import os
import secrets
from datetime import datetime, date
from calendar import monthrange
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Handle DATABASE_URL - Railway uses postgres:// but SQLAlchemy needs postgresql://
database_url = os.environ.get('DATABASE_URL', 'sqlite:///budget.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
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


# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_upload(file, subfolder):
    if file and file.filename and allowed_file(file.filename):
        filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
        folder_path = os.path.join(UPLOAD_FOLDER, subfolder)
        os.makedirs(folder_path, exist_ok=True)
        file.save(os.path.join(folder_path, filename))
        return filename
    return None

def delete_upload(filename, subfolder):
    if filename:
        filepath = os.path.join(UPLOAD_FOLDER, subfolder, filename)
        if os.path.exists(filepath):
            os.remove(filepath)


# Currency configuration (PHP and USD prioritized)
CURRENCIES = {
    # Prioritized
    'PHP': {'name': 'Philippine Peso', 'symbol': '₱'},
    'USD': {'name': 'US Dollar', 'symbol': '$'},
    # Major currencies
    'EUR': {'name': 'Euro', 'symbol': '€'},
    'GBP': {'name': 'British Pound', 'symbol': '£'},
    'JPY': {'name': 'Japanese Yen', 'symbol': '¥'},
    'CNY': {'name': 'Chinese Yuan', 'symbol': '¥'},
    'KRW': {'name': 'South Korean Won', 'symbol': '₩'},
    'INR': {'name': 'Indian Rupee', 'symbol': '₹'},
    'AUD': {'name': 'Australian Dollar', 'symbol': 'A$'},
    'CAD': {'name': 'Canadian Dollar', 'symbol': 'C$'},
    'SGD': {'name': 'Singapore Dollar', 'symbol': 'S$'},
    'HKD': {'name': 'Hong Kong Dollar', 'symbol': 'HK$'},
    'MYR': {'name': 'Malaysian Ringgit', 'symbol': 'RM'},
    'THB': {'name': 'Thai Baht', 'symbol': '฿'},
    'IDR': {'name': 'Indonesian Rupiah', 'symbol': 'Rp'},
    'VND': {'name': 'Vietnamese Dong', 'symbol': '₫'},
    'TWD': {'name': 'Taiwan Dollar', 'symbol': 'NT$'},
    'NZD': {'name': 'New Zealand Dollar', 'symbol': 'NZ$'},
    'CHF': {'name': 'Swiss Franc', 'symbol': 'CHF'},
    'SEK': {'name': 'Swedish Krona', 'symbol': 'kr'},
    'NOK': {'name': 'Norwegian Krone', 'symbol': 'kr'},
    'DKK': {'name': 'Danish Krone', 'symbol': 'kr'},
    'MXN': {'name': 'Mexican Peso', 'symbol': 'MX$'},
    'BRL': {'name': 'Brazilian Real', 'symbol': 'R$'},
    'ARS': {'name': 'Argentine Peso', 'symbol': 'AR$'},
    'CLP': {'name': 'Chilean Peso', 'symbol': 'CL$'},
    'COP': {'name': 'Colombian Peso', 'symbol': 'CO$'},
    'PEN': {'name': 'Peruvian Sol', 'symbol': 'S/'},
    'ZAR': {'name': 'South African Rand', 'symbol': 'R'},
    'AED': {'name': 'UAE Dirham', 'symbol': 'د.إ'},
    'SAR': {'name': 'Saudi Riyal', 'symbol': '﷼'},
    'QAR': {'name': 'Qatari Riyal', 'symbol': 'QR'},
    'KWD': {'name': 'Kuwaiti Dinar', 'symbol': 'KD'},
    'BHD': {'name': 'Bahraini Dinar', 'symbol': 'BD'},
    'OMR': {'name': 'Omani Rial', 'symbol': 'OMR'},
    'EGP': {'name': 'Egyptian Pound', 'symbol': 'E£'},
    'TRY': {'name': 'Turkish Lira', 'symbol': '₺'},
    'RUB': {'name': 'Russian Ruble', 'symbol': '₽'},
    'PLN': {'name': 'Polish Zloty', 'symbol': 'zł'},
    'CZK': {'name': 'Czech Koruna', 'symbol': 'Kč'},
    'HUF': {'name': 'Hungarian Forint', 'symbol': 'Ft'},
    'RON': {'name': 'Romanian Leu', 'symbol': 'lei'},
    'BGN': {'name': 'Bulgarian Lev', 'symbol': 'лв'},
    'HRK': {'name': 'Croatian Kuna', 'symbol': 'kn'},
    'ISK': {'name': 'Icelandic Krona', 'symbol': 'kr'},
    'ILS': {'name': 'Israeli Shekel', 'symbol': '₪'},
    'PKR': {'name': 'Pakistani Rupee', 'symbol': '₨'},
    'BDT': {'name': 'Bangladeshi Taka', 'symbol': '৳'},
    'LKR': {'name': 'Sri Lankan Rupee', 'symbol': 'Rs'},
    'NPR': {'name': 'Nepalese Rupee', 'symbol': 'रू'},
    'MMK': {'name': 'Myanmar Kyat', 'symbol': 'K'},
    'KHR': {'name': 'Cambodian Riel', 'symbol': '៛'},
    'LAK': {'name': 'Lao Kip', 'symbol': '₭'},
    'BND': {'name': 'Brunei Dollar', 'symbol': 'B$'},
    'NGN': {'name': 'Nigerian Naira', 'symbol': '₦'},
    'KES': {'name': 'Kenyan Shilling', 'symbol': 'KSh'},
    'GHS': {'name': 'Ghanaian Cedi', 'symbol': 'GH₵'},
    'XOF': {'name': 'West African CFA', 'symbol': 'CFA'},
    'XAF': {'name': 'Central African CFA', 'symbol': 'FCFA'},
    'MAD': {'name': 'Moroccan Dirham', 'symbol': 'MAD'},
    'TND': {'name': 'Tunisian Dinar', 'symbol': 'DT'},
    'JOD': {'name': 'Jordanian Dinar', 'symbol': 'JD'},
    'LBP': {'name': 'Lebanese Pound', 'symbol': 'L£'},
    'UAH': {'name': 'Ukrainian Hryvnia', 'symbol': '₴'},
    'BTC': {'name': 'Bitcoin', 'symbol': '₿'},
}

def get_currency_symbol(code):
    """Get currency symbol from code."""
    return CURRENCIES.get(code, {}).get('symbol', code)


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(100))
    theme = db.Column(db.String(10), default='dark')
    currency = db.Column(db.String(3), default='PHP')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    incomes = db.relationship('Income', backref='user', lazy=True, cascade='all, delete-orphan')
    expenses = db.relationship('Expense', backref='user', lazy=True, cascade='all, delete-orphan')
    credentials = db.relationship('Credential', backref='user', lazy=True, cascade='all, delete-orphan')
    links = db.relationship('Link', backref='user', lazy=True, cascade='all, delete-orphan')
    income_categories = db.relationship('IncomeCategory', backref='user', lazy=True, cascade='all, delete-orphan')
    expense_categories = db.relationship('ExpenseCategory', backref='user', lazy=True, cascade='all, delete-orphan')
    clients = db.relationship('Client', backref='user', lazy=True, cascade='all, delete-orphan')
    bank_accounts = db.relationship('BankAccount', backref='user', lazy=True, cascade='all, delete-orphan')
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True, cascade='all, delete-orphan')
    api_keys = db.relationship('ApiKey', backref='user', lazy=True, cascade='all, delete-orphan')


class IncomeCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    icon = db.Column(db.String(50), default='cash')
    color = db.Column(db.String(7), default='#22c55e')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    incomes = db.relationship('Income', backref='category', lazy=True)


class ExpenseCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    icon = db.Column(db.String(50), default='cart')
    color = db.Column(db.String(7), default='#ef4444')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    expenses = db.relationship('Expense', backref='category', lazy=True)


class BankAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    icon = db.Column(db.String(50), default='bank')
    color = db.Column(db.String(7), default='#6366f1')
    notes = db.Column(db.Text)
    image_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    incomes = db.relationship('Income', backref='client', lazy=True)


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)
    entity_id = db.Column(db.Integer)
    description = db.Column(db.String(255))
    amount = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('income_category.id'), nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=True)
    image_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('expense_category.id'), nullable=True)
    image_filename = db.Column(db.String(255))
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


@app.context_processor
def inject_currency():
    """Make currency symbol available in all templates."""
    if current_user.is_authenticated:
        currency_code = current_user.currency or 'PHP'
        return {
            'currency_symbol': get_currency_symbol(currency_code),
            'currency_code': currency_code
        }
    return {'currency_symbol': '₱', 'currency_code': 'PHP'}


# Activity logging helper
def log_activity(user_id, action, entity_type, entity_id=None, description=None, amount=None):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        description=description,
        amount=amount
    )
    db.session.add(log)
    db.session.commit()


# API Key authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'success': False, 'error': 'Missing API key'}), 401

        key_record = ApiKey.query.filter_by(key=api_key, is_active=True).first()
        if not key_record:
            return jsonify({'success': False, 'error': 'Invalid API key'}), 401

        request.api_user_id = key_record.user_id
        return f(*args, **kwargs)
    return decorated


# Helper to calculate user level based on total transactions
def get_user_stats(user_id):
    total_income = db.session.query(db.func.sum(Income.amount)).filter_by(user_id=user_id).scalar() or 0
    total_expenses = db.session.query(db.func.sum(Expense.amount)).filter_by(user_id=user_id).scalar() or 0
    total_transactions = Income.query.filter_by(user_id=user_id).count() + Expense.query.filter_by(user_id=user_id).count()

    # Level system: every 10 transactions = 1 level
    level = (total_transactions // 10) + 1
    xp = total_transactions % 10
    xp_needed = 10

    # Savings rate
    savings_rate = 0
    if total_income > 0:
        savings_rate = ((total_income - total_expenses) / total_income) * 100

    return {
        'level': level,
        'xp': xp,
        'xp_needed': xp_needed,
        'total_transactions': total_transactions,
        'savings_rate': max(0, savings_rate),
        'total_income': total_income,
        'total_expenses': total_expenses,
        'balance': total_income - total_expenses
    }


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

        # Create default categories for new user
        default_income_cats = [
            ('Salary', 'briefcase', '#22c55e'),
            ('Freelance', 'laptop', '#10b981'),
            ('Investment', 'graph-up', '#14b8a6'),
            ('Other', 'cash', '#6ee7b7')
        ]
        default_expense_cats = [
            ('Food', 'egg-fried', '#ef4444'),
            ('Transport', 'car-front', '#f97316'),
            ('Shopping', 'bag', '#ec4899'),
            ('Bills', 'receipt', '#8b5cf6'),
            ('Entertainment', 'controller', '#6366f1'),
            ('Other', 'three-dots', '#a3a3a3')
        ]

        for name, icon, color in default_income_cats:
            cat = IncomeCategory(user_id=user.id, name=name, icon=icon, color=color)
            db.session.add(cat)

        for name, icon, color in default_expense_cats:
            cat = ExpenseCategory(user_id=user.id, name=name, icon=icon, color=color)
            db.session.add(cat)

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
    stats = get_user_stats(current_user.id)

    recent_income = Income.query.filter_by(user_id=current_user.id).order_by(Income.date.desc()).limit(5).all()
    recent_expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).limit(5).all()

    # Get bank accounts total
    bank_total = db.session.query(db.func.sum(BankAccount.balance)).filter_by(user_id=current_user.id).scalar() or 0
    bank_count = BankAccount.query.filter_by(user_id=current_user.id).count()

    # Get current month data
    today = date.today()
    month_income = db.session.query(db.func.sum(Income.amount)).filter(
        Income.user_id == current_user.id,
        db.extract('year', Income.date) == today.year,
        db.extract('month', Income.date) == today.month
    ).scalar() or 0

    month_expenses = db.session.query(db.func.sum(Expense.amount)).filter(
        Expense.user_id == current_user.id,
        db.extract('year', Expense.date) == today.year,
        db.extract('month', Expense.date) == today.month
    ).scalar() or 0

    return render_template('dashboard.html',
                         stats=stats,
                         recent_income=recent_income,
                         recent_expenses=recent_expenses,
                         bank_total=bank_total,
                         bank_count=bank_count,
                         month_income=month_income,
                         month_expenses=month_expenses,
                         current_month=today.strftime('%B %Y'))


# Income routes
@app.route('/income')
@login_required
def income_list():
    incomes = Income.query.filter_by(user_id=current_user.id).order_by(Income.date.desc()).all()
    categories = IncomeCategory.query.filter_by(user_id=current_user.id).order_by(IncomeCategory.name).all()
    total = sum(i.amount for i in incomes)
    return render_template('income.html', incomes=incomes, categories=categories, total=total)


@app.route('/income/add', methods=['GET', 'POST'])
@login_required
def income_add():
    categories = IncomeCategory.query.filter_by(user_id=current_user.id).order_by(IncomeCategory.name).all()
    clients = Client.query.filter_by(user_id=current_user.id).order_by(Client.name).all()

    if request.method == 'POST':
        category_id = request.form.get('category_id')
        client_id = request.form.get('client_id')

        image_filename = None
        if 'image' in request.files:
            image_filename = save_upload(request.files['image'], 'income')

        income = Income(
            user_id=current_user.id,
            source=request.form.get('source'),
            amount=float(request.form.get('amount')),
            date=datetime.strptime(request.form.get('date'), '%Y-%m-%d').date(),
            notes=request.form.get('notes'),
            category_id=int(category_id) if category_id else None,
            client_id=int(client_id) if client_id else None,
            image_filename=image_filename
        )
        db.session.add(income)
        db.session.commit()

        log_activity(current_user.id, 'created', 'income', income.id,
                    f'+${income.amount:.2f} {income.source}', income.amount)

        flash('Income added! +XP', 'success')
        return redirect(url_for('income_list'))
    return render_template('income_form.html', categories=categories, clients=clients)


@app.route('/income/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def income_edit(id):
    income = Income.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    categories = IncomeCategory.query.filter_by(user_id=current_user.id).order_by(IncomeCategory.name).all()
    clients = Client.query.filter_by(user_id=current_user.id).order_by(Client.name).all()

    if request.method == 'POST':
        category_id = request.form.get('category_id')
        client_id = request.form.get('client_id')

        if 'image' in request.files and request.files['image'].filename:
            if income.image_filename:
                delete_upload(income.image_filename, 'income')
            income.image_filename = save_upload(request.files['image'], 'income')

        if request.form.get('remove_image'):
            delete_upload(income.image_filename, 'income')
            income.image_filename = None

        income.source = request.form.get('source')
        income.amount = float(request.form.get('amount'))
        income.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        income.notes = request.form.get('notes')
        income.category_id = int(category_id) if category_id else None
        income.client_id = int(client_id) if client_id else None
        db.session.commit()

        log_activity(current_user.id, 'updated', 'income', income.id,
                    f'Updated: {income.source}', income.amount)

        flash('Income updated!', 'success')
        return redirect(url_for('income_list'))
    return render_template('income_form.html', income=income, categories=categories, clients=clients)


@app.route('/income/delete/<int:id>', methods=['POST'])
@login_required
def income_delete(id):
    income = Income.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    log_activity(current_user.id, 'deleted', 'income', income.id,
                f'Deleted: {income.source}', income.amount)

    if income.image_filename:
        delete_upload(income.image_filename, 'income')

    db.session.delete(income)
    db.session.commit()
    flash('Income deleted!', 'success')
    return redirect(url_for('income_list'))


# Income Category routes
@app.route('/income/categories')
@login_required
def income_categories():
    categories = IncomeCategory.query.filter_by(user_id=current_user.id).order_by(IncomeCategory.name).all()
    return render_template('income_categories.html', categories=categories)


@app.route('/income/categories/add', methods=['GET', 'POST'])
@login_required
def income_category_add():
    if request.method == 'POST':
        category = IncomeCategory(
            user_id=current_user.id,
            name=request.form.get('name'),
            icon=request.form.get('icon', 'cash'),
            color=request.form.get('color', '#22c55e')
        )
        db.session.add(category)
        db.session.commit()
        flash('Income type created!', 'success')
        return redirect(url_for('income_categories'))
    return render_template('income_category_form.html')


@app.route('/income/categories/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def income_category_edit(id):
    category = IncomeCategory.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        category.name = request.form.get('name')
        category.icon = request.form.get('icon', 'cash')
        category.color = request.form.get('color', '#22c55e')
        db.session.commit()
        flash('Income type updated!', 'success')
        return redirect(url_for('income_categories'))
    return render_template('income_category_form.html', category=category)


@app.route('/income/categories/delete/<int:id>', methods=['POST'])
@login_required
def income_category_delete(id):
    category = IncomeCategory.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    Income.query.filter_by(category_id=id).update({'category_id': None})
    db.session.delete(category)
    db.session.commit()
    flash('Income type deleted!', 'success')
    return redirect(url_for('income_categories'))


# Expense routes
@app.route('/expenses')
@login_required
def expense_list():
    expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).all()
    categories = ExpenseCategory.query.filter_by(user_id=current_user.id).order_by(ExpenseCategory.name).all()
    total = sum(e.amount for e in expenses)
    return render_template('expenses.html', expenses=expenses, categories=categories, total=total)


@app.route('/expenses/add', methods=['GET', 'POST'])
@login_required
def expense_add():
    categories = ExpenseCategory.query.filter_by(user_id=current_user.id).order_by(ExpenseCategory.name).all()

    if request.method == 'POST':
        category_id = request.form.get('category_id')

        image_filename = None
        if 'image' in request.files:
            image_filename = save_upload(request.files['image'], 'expenses')

        expense = Expense(
            user_id=current_user.id,
            description=request.form.get('description'),
            amount=float(request.form.get('amount')),
            date=datetime.strptime(request.form.get('date'), '%Y-%m-%d').date(),
            notes=request.form.get('notes'),
            category_id=int(category_id) if category_id else None,
            image_filename=image_filename
        )
        db.session.add(expense)
        db.session.commit()

        log_activity(current_user.id, 'created', 'expense', expense.id,
                    f'-${expense.amount:.2f} {expense.description}', expense.amount)

        flash('Expense added! +XP', 'success')
        return redirect(url_for('expense_list'))
    return render_template('expense_form.html', categories=categories)


@app.route('/expenses/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def expense_edit(id):
    expense = Expense.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    categories = ExpenseCategory.query.filter_by(user_id=current_user.id).order_by(ExpenseCategory.name).all()

    if request.method == 'POST':
        category_id = request.form.get('category_id')

        if 'image' in request.files and request.files['image'].filename:
            if expense.image_filename:
                delete_upload(expense.image_filename, 'expenses')
            expense.image_filename = save_upload(request.files['image'], 'expenses')

        if request.form.get('remove_image'):
            delete_upload(expense.image_filename, 'expenses')
            expense.image_filename = None

        expense.description = request.form.get('description')
        expense.amount = float(request.form.get('amount'))
        expense.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        expense.notes = request.form.get('notes')
        expense.category_id = int(category_id) if category_id else None
        db.session.commit()

        log_activity(current_user.id, 'updated', 'expense', expense.id,
                    f'Updated: {expense.description}', expense.amount)

        flash('Expense updated!', 'success')
        return redirect(url_for('expense_list'))
    return render_template('expense_form.html', expense=expense, categories=categories)


@app.route('/expenses/delete/<int:id>', methods=['POST'])
@login_required
def expense_delete(id):
    expense = Expense.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    log_activity(current_user.id, 'deleted', 'expense', expense.id,
                f'Deleted: {expense.description}', expense.amount)

    if expense.image_filename:
        delete_upload(expense.image_filename, 'expenses')

    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted!', 'success')
    return redirect(url_for('expense_list'))


# Expense Category routes
@app.route('/expenses/categories')
@login_required
def expense_categories():
    categories = ExpenseCategory.query.filter_by(user_id=current_user.id).order_by(ExpenseCategory.name).all()
    return render_template('expense_categories.html', categories=categories)


@app.route('/expenses/categories/add', methods=['GET', 'POST'])
@login_required
def expense_category_add():
    if request.method == 'POST':
        category = ExpenseCategory(
            user_id=current_user.id,
            name=request.form.get('name'),
            icon=request.form.get('icon', 'cart'),
            color=request.form.get('color', '#ef4444')
        )
        db.session.add(category)
        db.session.commit()
        flash('Expense type created!', 'success')
        return redirect(url_for('expense_categories'))
    return render_template('expense_category_form.html')


@app.route('/expenses/categories/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def expense_category_edit(id):
    category = ExpenseCategory.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        category.name = request.form.get('name')
        category.icon = request.form.get('icon', 'cart')
        category.color = request.form.get('color', '#ef4444')
        db.session.commit()
        flash('Expense type updated!', 'success')
        return redirect(url_for('expense_categories'))
    return render_template('expense_category_form.html', category=category)


@app.route('/expenses/categories/delete/<int:id>', methods=['POST'])
@login_required
def expense_category_delete(id):
    category = ExpenseCategory.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    Expense.query.filter_by(category_id=id).update({'category_id': None})
    db.session.delete(category)
    db.session.commit()
    flash('Expense type deleted!', 'success')
    return redirect(url_for('expense_categories'))


# Balance / Bank Account routes
@app.route('/balance')
@login_required
def balance_list():
    accounts = BankAccount.query.filter_by(user_id=current_user.id).order_by(BankAccount.name).all()
    total = sum(a.balance for a in accounts)
    return render_template('balance.html', accounts=accounts, total=total)


@app.route('/balance/add', methods=['GET', 'POST'])
@login_required
def balance_add():
    if request.method == 'POST':
        image_filename = None
        if 'image' in request.files:
            image_filename = save_upload(request.files['image'], 'banks')

        account = BankAccount(
            user_id=current_user.id,
            name=request.form.get('name'),
            balance=float(request.form.get('balance', 0)),
            icon=request.form.get('icon', 'bank'),
            color=request.form.get('color', '#6366f1'),
            notes=request.form.get('notes'),
            image_filename=image_filename
        )
        db.session.add(account)
        db.session.commit()

        log_activity(current_user.id, 'created', 'bank_account', account.id,
                    f'Added bank: {account.name}', account.balance)

        flash('Bank account added!', 'success')
        return redirect(url_for('balance_list'))
    return render_template('balance_form.html')


@app.route('/balance/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def balance_edit(id):
    account = BankAccount.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        if 'image' in request.files and request.files['image'].filename:
            if account.image_filename:
                delete_upload(account.image_filename, 'banks')
            account.image_filename = save_upload(request.files['image'], 'banks')

        if request.form.get('remove_image'):
            delete_upload(account.image_filename, 'banks')
            account.image_filename = None

        account.name = request.form.get('name')
        account.balance = float(request.form.get('balance', 0))
        account.icon = request.form.get('icon', 'bank')
        account.color = request.form.get('color', '#6366f1')
        account.notes = request.form.get('notes')
        db.session.commit()

        log_activity(current_user.id, 'updated', 'bank_account', account.id,
                    f'Updated bank: {account.name}', account.balance)

        flash('Bank account updated!', 'success')
        return redirect(url_for('balance_list'))
    return render_template('balance_form.html', account=account)


@app.route('/balance/delete/<int:id>', methods=['POST'])
@login_required
def balance_delete(id):
    account = BankAccount.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    log_activity(current_user.id, 'deleted', 'bank_account', account.id,
                f'Deleted bank: {account.name}', account.balance)

    if account.image_filename:
        delete_upload(account.image_filename, 'banks')

    db.session.delete(account)
    db.session.commit()
    flash('Bank account deleted!', 'success')
    return redirect(url_for('balance_list'))


# Client routes
@app.route('/clients')
@login_required
def client_list():
    clients = Client.query.filter_by(user_id=current_user.id).order_by(Client.name).all()
    return render_template('clients.html', clients=clients)


@app.route('/clients/add', methods=['GET', 'POST'])
@login_required
def client_add():
    if request.method == 'POST':
        client = Client(
            user_id=current_user.id,
            name=request.form.get('name'),
            email=request.form.get('email'),
            notes=request.form.get('notes')
        )
        db.session.add(client)
        db.session.commit()
        flash('Client added!', 'success')
        return redirect(url_for('client_list'))
    return render_template('client_form.html')


@app.route('/clients/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def client_edit(id):
    client = Client.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        client.name = request.form.get('name')
        client.email = request.form.get('email')
        client.notes = request.form.get('notes')
        db.session.commit()
        flash('Client updated!', 'success')
        return redirect(url_for('client_list'))
    return render_template('client_form.html', client=client)


@app.route('/clients/delete/<int:id>', methods=['POST'])
@login_required
def client_delete(id):
    client = Client.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    Income.query.filter_by(client_id=id).update({'client_id': None})
    db.session.delete(client)
    db.session.commit()
    flash('Client deleted!', 'success')
    return redirect(url_for('client_list'))


# Calendar routes
@app.route('/calendar')
@login_required
def calendar_view():
    year = request.args.get('year', date.today().year, type=int)
    month = request.args.get('month', date.today().month, type=int)

    if month > 12:
        month = 1
        year += 1
    elif month < 1:
        month = 12
        year -= 1

    return render_template('calendar.html', year=year, month=month)


@app.route('/api/calendar/<int:year>/<int:month>')
@login_required
def calendar_data(year, month):
    incomes = Income.query.filter(
        Income.user_id == current_user.id,
        db.extract('year', Income.date) == year,
        db.extract('month', Income.date) == month
    ).all()

    expenses = Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('year', Expense.date) == year,
        db.extract('month', Expense.date) == month
    ).all()

    days_data = {}

    for income in incomes:
        day = income.date.day
        if day not in days_data:
            days_data[day] = {'income': [], 'expenses': []}
        days_data[day]['income'].append({
            'id': income.id,
            'source': income.source,
            'amount': income.amount
        })

    for expense in expenses:
        day = expense.date.day
        if day not in days_data:
            days_data[day] = {'income': [], 'expenses': []}
        days_data[day]['expenses'].append({
            'id': expense.id,
            'description': expense.description,
            'amount': expense.amount
        })

    total_income = sum(i.amount for i in incomes)
    total_expenses = sum(e.amount for e in expenses)

    return jsonify({
        'days': days_data,
        'total_income': total_income,
        'total_expenses': total_expenses,
        'balance': total_income - total_expenses,
        'days_in_month': monthrange(year, month)[1],
        'first_day_weekday': date(year, month, 1).weekday()
    })


# Activity log routes
@app.route('/activity')
@login_required
def activity_log():
    entity_filter = request.args.get('entity', '')
    action_filter = request.args.get('action', '')

    query = ActivityLog.query.filter_by(user_id=current_user.id)

    if entity_filter:
        query = query.filter_by(entity_type=entity_filter)
    if action_filter:
        query = query.filter_by(action=action_filter)

    logs = query.order_by(ActivityLog.created_at.desc()).limit(100).all()

    return render_template('activity.html', logs=logs,
                          entity_filter=entity_filter, action_filter=action_filter)


# API Key management routes
@app.route('/settings/api')
@login_required
def api_settings():
    keys = ApiKey.query.filter_by(user_id=current_user.id).order_by(ApiKey.created_at.desc()).all()
    return render_template('api_settings.html', keys=keys)


@app.route('/settings/api/generate', methods=['POST'])
@login_required
def api_key_generate():
    name = request.form.get('name', 'API Key')
    key = secrets.token_hex(32)

    api_key = ApiKey(
        user_id=current_user.id,
        key=key,
        name=name
    )
    db.session.add(api_key)
    db.session.commit()

    flash(f'API key generated: {key}', 'success')
    return redirect(url_for('api_settings'))


@app.route('/settings/api/delete/<int:id>', methods=['POST'])
@login_required
def api_key_delete(id):
    api_key = ApiKey.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(api_key)
    db.session.commit()
    flash('API key revoked!', 'success')
    return redirect(url_for('api_settings'))


# Settings routes
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_user.display_name = request.form.get('display_name', '').strip() or None
        db.session.commit()
        flash('Settings updated!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', currencies=CURRENCIES)


@app.route('/settings/password', methods=['POST'])
@login_required
def settings_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not check_password_hash(current_user.password_hash, current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('settings'))

    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('settings'))

    if len(new_password) < 8:
        flash('Password must be at least 8 characters', 'error')
        return redirect(url_for('settings'))

    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/theme', methods=['POST'])
@login_required
def settings_theme():
    theme = request.form.get('theme', 'dark')
    if theme in ['dark', 'light']:
        current_user.theme = theme
        db.session.commit()
    return redirect(url_for('settings'))


@app.route('/settings/currency', methods=['POST'])
@login_required
def settings_currency():
    currency = request.form.get('currency', 'PHP')
    if currency in CURRENCIES:
        current_user.currency = currency
        db.session.commit()
        flash(f'Currency changed to {CURRENCIES[currency]["name"]}', 'success')
    return redirect(url_for('settings'))


# External API endpoint
@app.route('/api/v1/income', methods=['POST'])
@require_api_key
def api_add_income():
    data = request.get_json()

    if not data:
        return jsonify({'success': False, 'error': 'Invalid JSON'}), 400

    name = data.get('name')
    amount = data.get('amount')

    if not name or amount is None:
        return jsonify({'success': False, 'error': 'Missing required fields: name, amount'}), 400

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'Invalid amount'}), 400

    income_date = date.today()
    if data.get('date'):
        try:
            income_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    category_id = None
    if data.get('category'):
        category = IncomeCategory.query.filter_by(
            user_id=request.api_user_id,
            name=data['category']
        ).first()
        if not category:
            category = IncomeCategory(user_id=request.api_user_id, name=data['category'])
            db.session.add(category)
            db.session.flush()
        category_id = category.id

    client_id = None
    if data.get('client'):
        client = Client.query.filter_by(
            user_id=request.api_user_id,
            name=data['client']
        ).first()
        if not client:
            client = Client(user_id=request.api_user_id, name=data['client'])
            db.session.add(client)
            db.session.flush()
        client_id = client.id

    income = Income(
        user_id=request.api_user_id,
        source=name,
        amount=amount,
        date=income_date,
        notes=data.get('notes'),
        category_id=category_id,
        client_id=client_id
    )
    db.session.add(income)
    db.session.commit()

    return jsonify({
        'success': True,
        'income_id': income.id,
        'message': 'Income added successfully'
    })


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
        flash('Credential added!', 'success')
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
        flash('Credential updated!', 'success')
        return redirect(url_for('credential_list'))
    return render_template('credential_form.html', credential=credential)


@app.route('/credentials/delete/<int:id>', methods=['POST'])
@login_required
def credential_delete(id):
    credential = Credential.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(credential)
    db.session.commit()
    flash('Credential deleted!', 'success')
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
        flash('Link added!', 'success')
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
        flash('Link updated!', 'success')
        return redirect(url_for('link_list'))
    return render_template('link_form.html', link=link)


@app.route('/links/delete/<int:id>', methods=['POST'])
@login_required
def link_delete(id):
    link = Link.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(link)
    db.session.commit()
    flash('Link deleted!', 'success')
    return redirect(url_for('link_list'))


# Database migration helper
def run_migrations():
    """Add missing columns to existing tables."""
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)

    def table_has_column(table, column):
        try:
            columns = [c['name'] for c in inspector.get_columns(table)]
            return column in columns
        except:
            return True  # Assume exists if we can't check

    def add_column(table, column, col_type, default=None):
        if not table_has_column(table, column):
            # Quote table name for PostgreSQL reserved words
            quoted_table = f'"{table}"' if table == 'user' else table
            sql = f'ALTER TABLE {quoted_table} ADD COLUMN {column} {col_type}'
            if default is not None:
                sql += f" DEFAULT '{default}'"
            try:
                with db.engine.connect() as conn:
                    conn.execute(text(sql))
                    conn.commit()
                print(f"Added column {column} to {table}")
            except Exception as e:
                print(f"Column {column} on {table}: {e}")

    # User table columns
    add_column('user', 'display_name', 'VARCHAR(100)')
    add_column('user', 'theme', 'VARCHAR(10)', 'dark')
    add_column('user', 'currency', 'VARCHAR(3)', 'PHP')

    # Transaction image columns
    add_column('income', 'image_filename', 'VARCHAR(255)')
    add_column('expense', 'image_filename', 'VARCHAR(255)')
    add_column('bank_account', 'image_filename', 'VARCHAR(255)')


# Initialize database
with app.app_context():
    db.create_all()
    try:
        run_migrations()
    except Exception as e:
        print(f"Migration error: {e}")


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
