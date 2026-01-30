import os
import secrets
from datetime import datetime, date
from calendar import monthrange
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
    folders = db.relationship('Folder', backref='user', lazy=True, cascade='all, delete-orphan')
    clients = db.relationship('Client', backref='user', lazy=True, cascade='all, delete-orphan')
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True, cascade='all, delete-orphan')
    api_keys = db.relationship('ApiKey', backref='user', lazy=True, cascade='all, delete-orphan')


class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(7), default='#6366f1')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    incomes = db.relationship('Income', backref='folder', lazy=True)
    expenses = db.relationship('Expense', backref='folder', lazy=True)


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
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
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

    # Get current month data for calendar preview
    today = date.today()
    month_income = Income.query.filter(
        Income.user_id == current_user.id,
        db.extract('year', Income.date) == today.year,
        db.extract('month', Income.date) == today.month
    ).all()
    month_expenses = Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('year', Expense.date) == today.year,
        db.extract('month', Expense.date) == today.month
    ).all()

    month_income_total = sum(i.amount for i in month_income)
    month_expense_total = sum(e.amount for e in month_expenses)

    return render_template('dashboard.html',
                         total_income=total_income,
                         total_expenses=total_expenses,
                         balance=balance,
                         recent_income=recent_income,
                         recent_expenses=recent_expenses,
                         month_income_total=month_income_total,
                         month_expense_total=month_expense_total,
                         current_month=today.strftime('%B %Y'))


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
    folders = Folder.query.filter_by(user_id=current_user.id).order_by(Folder.name).all()
    clients = Client.query.filter_by(user_id=current_user.id).order_by(Client.name).all()

    if request.method == 'POST':
        folder_id = request.form.get('folder_id')
        client_id = request.form.get('client_id')

        income = Income(
            user_id=current_user.id,
            source=request.form.get('source'),
            amount=float(request.form.get('amount')),
            date=datetime.strptime(request.form.get('date'), '%Y-%m-%d').date(),
            notes=request.form.get('notes'),
            folder_id=int(folder_id) if folder_id else None,
            client_id=int(client_id) if client_id else None
        )
        db.session.add(income)
        db.session.commit()

        log_activity(current_user.id, 'created', 'income', income.id,
                    f'Added income: {income.source}', income.amount)

        flash('Income added successfully!', 'success')
        return redirect(url_for('income_list'))
    return render_template('income_form.html', folders=folders, clients=clients)


@app.route('/income/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def income_edit(id):
    income = Income.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    folders = Folder.query.filter_by(user_id=current_user.id).order_by(Folder.name).all()
    clients = Client.query.filter_by(user_id=current_user.id).order_by(Client.name).all()

    if request.method == 'POST':
        folder_id = request.form.get('folder_id')
        client_id = request.form.get('client_id')

        income.source = request.form.get('source')
        income.amount = float(request.form.get('amount'))
        income.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        income.notes = request.form.get('notes')
        income.folder_id = int(folder_id) if folder_id else None
        income.client_id = int(client_id) if client_id else None
        db.session.commit()

        log_activity(current_user.id, 'updated', 'income', income.id,
                    f'Updated income: {income.source}', income.amount)

        flash('Income updated successfully!', 'success')
        return redirect(url_for('income_list'))
    return render_template('income_form.html', income=income, folders=folders, clients=clients)


@app.route('/income/delete/<int:id>', methods=['POST'])
@login_required
def income_delete(id):
    income = Income.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    log_activity(current_user.id, 'deleted', 'income', income.id,
                f'Deleted income: {income.source}', income.amount)

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
    folders = Folder.query.filter_by(user_id=current_user.id).order_by(Folder.name).all()

    if request.method == 'POST':
        folder_id = request.form.get('folder_id')

        expense = Expense(
            user_id=current_user.id,
            category=request.form.get('category'),
            description=request.form.get('description'),
            amount=float(request.form.get('amount')),
            date=datetime.strptime(request.form.get('date'), '%Y-%m-%d').date(),
            notes=request.form.get('notes'),
            folder_id=int(folder_id) if folder_id else None
        )
        db.session.add(expense)
        db.session.commit()

        log_activity(current_user.id, 'created', 'expense', expense.id,
                    f'Added expense: {expense.description}', expense.amount)

        flash('Expense added successfully!', 'success')
        return redirect(url_for('expense_list'))
    return render_template('expense_form.html', folders=folders)


@app.route('/expenses/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def expense_edit(id):
    expense = Expense.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    folders = Folder.query.filter_by(user_id=current_user.id).order_by(Folder.name).all()

    if request.method == 'POST':
        folder_id = request.form.get('folder_id')

        expense.category = request.form.get('category')
        expense.description = request.form.get('description')
        expense.amount = float(request.form.get('amount'))
        expense.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        expense.notes = request.form.get('notes')
        expense.folder_id = int(folder_id) if folder_id else None
        db.session.commit()

        log_activity(current_user.id, 'updated', 'expense', expense.id,
                    f'Updated expense: {expense.description}', expense.amount)

        flash('Expense updated successfully!', 'success')
        return redirect(url_for('expense_list'))
    return render_template('expense_form.html', expense=expense, folders=folders)


@app.route('/expenses/delete/<int:id>', methods=['POST'])
@login_required
def expense_delete(id):
    expense = Expense.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    log_activity(current_user.id, 'deleted', 'expense', expense.id,
                f'Deleted expense: {expense.description}', expense.amount)

    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted successfully!', 'success')
    return redirect(url_for('expense_list'))


# Folder routes
@app.route('/folders')
@login_required
def folder_list():
    folders = Folder.query.filter_by(user_id=current_user.id).order_by(Folder.name).all()
    return render_template('folders.html', folders=folders)


@app.route('/folders/add', methods=['GET', 'POST'])
@login_required
def folder_add():
    if request.method == 'POST':
        folder = Folder(
            user_id=current_user.id,
            name=request.form.get('name'),
            color=request.form.get('color', '#6366f1')
        )
        db.session.add(folder)
        db.session.commit()

        log_activity(current_user.id, 'created', 'folder', folder.id,
                    f'Created folder: {folder.name}')

        flash('Folder created successfully!', 'success')
        return redirect(url_for('folder_list'))
    return render_template('folder_form.html')


@app.route('/folders/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def folder_edit(id):
    folder = Folder.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        folder.name = request.form.get('name')
        folder.color = request.form.get('color', '#6366f1')
        db.session.commit()

        log_activity(current_user.id, 'updated', 'folder', folder.id,
                    f'Updated folder: {folder.name}')

        flash('Folder updated successfully!', 'success')
        return redirect(url_for('folder_list'))
    return render_template('folder_form.html', folder=folder)


@app.route('/folders/delete/<int:id>', methods=['POST'])
@login_required
def folder_delete(id):
    folder = Folder.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    # Remove folder associations from income/expenses
    Income.query.filter_by(folder_id=id).update({'folder_id': None})
    Expense.query.filter_by(folder_id=id).update({'folder_id': None})

    log_activity(current_user.id, 'deleted', 'folder', folder.id,
                f'Deleted folder: {folder.name}')

    db.session.delete(folder)
    db.session.commit()
    flash('Folder deleted successfully!', 'success')
    return redirect(url_for('folder_list'))


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

        log_activity(current_user.id, 'created', 'client', client.id,
                    f'Created client: {client.name}')

        flash('Client added successfully!', 'success')
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

        log_activity(current_user.id, 'updated', 'client', client.id,
                    f'Updated client: {client.name}')

        flash('Client updated successfully!', 'success')
        return redirect(url_for('client_list'))
    return render_template('client_form.html', client=client)


@app.route('/clients/delete/<int:id>', methods=['POST'])
@login_required
def client_delete(id):
    client = Client.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    # Remove client associations from income
    Income.query.filter_by(client_id=id).update({'client_id': None})

    log_activity(current_user.id, 'deleted', 'client', client.id,
                f'Deleted client: {client.name}')

    db.session.delete(client)
    db.session.commit()
    flash('Client deleted successfully!', 'success')
    return redirect(url_for('client_list'))


# Calendar routes
@app.route('/calendar')
@login_required
def calendar_view():
    year = request.args.get('year', date.today().year, type=int)
    month = request.args.get('month', date.today().month, type=int)

    # Handle month overflow
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
    # Get income and expenses for the month
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

    # Build day data
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
            'category': expense.category,
            'amount': expense.amount
        })

    # Calculate totals
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

    log_activity(current_user.id, 'created', 'api_key', api_key.id,
                f'Generated API key: {name}')

    flash(f'API key generated: {key}', 'success')
    return redirect(url_for('api_settings'))


@app.route('/settings/api/delete/<int:id>', methods=['POST'])
@login_required
def api_key_delete(id):
    api_key = ApiKey.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    log_activity(current_user.id, 'deleted', 'api_key', api_key.id,
                f'Revoked API key: {api_key.name}')

    db.session.delete(api_key)
    db.session.commit()
    flash('API key revoked successfully!', 'success')
    return redirect(url_for('api_settings'))


# External API endpoint for n8n
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

    # Parse date or use today
    income_date = date.today()
    if data.get('date'):
        try:
            income_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    # Handle folder - auto-create if doesn't exist
    folder_id = None
    if data.get('folder'):
        folder = Folder.query.filter_by(
            user_id=request.api_user_id,
            name=data['folder']
        ).first()
        if not folder:
            folder = Folder(user_id=request.api_user_id, name=data['folder'])
            db.session.add(folder)
            db.session.flush()
        folder_id = folder.id

    # Handle client - auto-create if doesn't exist
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
        folder_id=folder_id,
        client_id=client_id
    )
    db.session.add(income)
    db.session.commit()

    log_activity(request.api_user_id, 'created', 'income', income.id,
                f'Added income via API: {name}', amount)

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

        log_activity(current_user.id, 'created', 'credential', credential.id,
                    f'Added credential: {credential.name}')

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

        log_activity(current_user.id, 'updated', 'credential', credential.id,
                    f'Updated credential: {credential.name}')

        flash('Credential updated successfully!', 'success')
        return redirect(url_for('credential_list'))
    return render_template('credential_form.html', credential=credential)


@app.route('/credentials/delete/<int:id>', methods=['POST'])
@login_required
def credential_delete(id):
    credential = Credential.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    log_activity(current_user.id, 'deleted', 'credential', credential.id,
                f'Deleted credential: {credential.name}')

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

        log_activity(current_user.id, 'created', 'link', link.id,
                    f'Added link: {link.name}')

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

        log_activity(current_user.id, 'updated', 'link', link.id,
                    f'Updated link: {link.name}')

        flash('Link updated successfully!', 'success')
        return redirect(url_for('link_list'))
    return render_template('link_form.html', link=link)


@app.route('/links/delete/<int:id>', methods=['POST'])
@login_required
def link_delete(id):
    link = Link.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    log_activity(current_user.id, 'deleted', 'link', link.id,
                f'Deleted link: {link.name}')

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
