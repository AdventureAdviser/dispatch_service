from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ваш_секретный_ключ'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dispatch.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Модель пользователя
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # dispatcher, operator, administrator

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    location = db.Column(db.String(120), nullable=False)
    substance = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Open')
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assigned_to = db.relationship('User', backref='incidents')

# Модель ресурса
class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    type = db.Column(db.String(50), nullable=False)            # 'personnel' or 'equipment'
    contact = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Ready')  # 'Ready' or 'In Progress'
    assigned_incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=True)
    assigned_incident = db.relationship('Incident', backref='resources')


@app.route('/')
@login_required
def index():
    open_count = Incident.query.filter(Incident.status != 'Closed').count()
    last_incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(5).all()
    return render_template('dashboard.html', open_count=open_count, last_incidents=last_incidents)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(username=request.form['username']).first()
        if u and u.check_password(request.form['password']):
            login_user(u)
            return redirect(url_for('index'))
        flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Инциденты: список, создание, редактирование
@app.route('/incidents')
@login_required
def incidents():
    q = Incident.query
    status = request.args.get('status')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    if status:
        q = q.filter_by(status=status)
    if date_from:
        df = datetime.datetime.fromisoformat(date_from)
        q = q.filter(Incident.timestamp >= df)
    if date_to:
        dt = datetime.datetime.fromisoformat(date_to)
        q = q.filter(Incident.timestamp <= dt)
    incidents_list = q.order_by(Incident.timestamp.desc()).all()
    statuses = ['Open', 'In Progress', 'Closed']
    return render_template('incidents.html', incidents=incidents_list, statuses=statuses)


@app.route('/incidents/new', methods=['GET', 'POST'])
@login_required
def new_incident():
    if request.method == 'POST':
        inc = Incident(
            location=request.form['location'],
            substance=request.form['substance'],
            description=request.form.get('description'),
            status='Open'
        )
        db.session.add(inc)
        db.session.commit()
        return redirect(url_for('incidents'))
    return render_template('new_incident.html')



@app.route('/incidents/<int:incident_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_incident(incident_id):
    inc = Incident.query.get_or_404(incident_id)
    users = User.query.filter(User.role.in_(['dispatcher','operator'])).all()
    statuses = ['Open', 'In Progress', 'Closed']
    if request.method == 'POST':
        inc.status = request.form['status']
        user_id = request.form.get('assigned_to')
        inc.assigned_to = User.query.get(user_id) if user_id else None
        db.session.commit()
        return redirect(url_for('incidents'))
    return render_template('edit_incident.html', incident=inc, users=users, statuses=statuses)

# Ресурсы: список
@app.route('/resources')
@login_required
def resources():
    res_list = Resource.query.order_by(Resource.name).all()
    return render_template('resources.html', resources=res_list)

# Добавление нового ресурса
@app.route('/resources/new', methods=['GET', 'POST'])
@login_required
def new_resource():
    if request.method == 'POST':
        res = Resource(
            name=request.form['name'],
            type=request.form['type'],
            contact=request.form.get('contact'),
            status='Ready'
        )
        db.session.add(res)
        db.session.commit()
        return redirect(url_for('resources'))
    return render_template('new_resource.html')

# Назначение ресурса на инцидент
@app.route('/resources/assign', methods=['GET', 'POST'])
@login_required
def assign_resource():
    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    resources = Resource.query.order_by(Resource.name).all()
    if request.method == 'POST':
        res_id = int(request.form['resource_id'])
        inc_id = int(request.form['incident_id'])
        res = Resource.query.get_or_404(res_id)
        res.assigned_incident = Incident.query.get_or_404(inc_id)
        res.status = 'In Progress'
        db.session.commit()
        return redirect(url_for('resources'))
    return render_template('assign_resource.html', incidents=incidents, resources=resources)


# Регистрация новых пользователей — только админ
@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.role != 'administrator':
        flash('Доступ запрещён', 'warning')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует', 'warning')
        else:
            new_user = User(username=username, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f"Пользователь {username} ({role}) создан", 'success')
            return redirect(url_for('index'))
    return render_template('register.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='administrator')
            admin.set_password('adminpass')
            db.session.add(admin)
            db.session.commit()
            print("Суперпользователь 'admin' создан с паролем 'adminpass'")
    app.run(debug=True)