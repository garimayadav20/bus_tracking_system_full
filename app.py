from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

# ✅ Hard-coded secret key and database URI for development
app.secret_key = "mysecretkey"

# ✅ Direct MySQL connection string with your password
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:Khushi%40123@localhost/bus_tracking"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# -------------------- MODELS --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))
    role = db.Column(db.String(10))

class Bus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bus_no = db.Column(db.String(20), unique=True)
    route = db.Column(db.String(100))
    driver_name = db.Column(db.String(50))

class BusLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- ROUTES --------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect('/register')
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User registered successfully!')
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('admin_dashboard') if user.role == 'admin' else url_for('student_dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect('/login')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return "Access Denied", 403
    if request.method == 'POST':
        bus_no = request.form['bus_no']
        route = request.form['route']
        driver_name = request.form['driver_name']
        new_bus = Bus(bus_no=bus_no, route=route, driver_name=driver_name)
        db.session.add(new_bus)
        db.session.commit()
    buses = Bus.query.all()
    return render_template('admin.html', buses=buses)

@app.route('/student')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return "Access Denied", 403
    buses = Bus.query.all()
    return render_template('student_dashboard.html', buses=buses)

@app.route('/driver')
def driver():
    return render_template('driver.html')

@app.route('/api/update-location', methods=['POST'])
def update_location():
    data = request.get_json()
    bus_id = data['bus_id']
    lat = data['lat']
    lng = data['lng']
    location = BusLocation(bus_id=bus_id, latitude=lat, longitude=lng)
    db.session.add(location)
    db.session.commit()
    return jsonify({"status": "location updated"})

@app.route('/api/bus-location/<int:bus_id>')
def get_location(bus_id):
    location = BusLocation.query.filter_by(bus_id=bus_id).order_by(BusLocation.timestamp.desc()).first()
    bus = Bus.query.get(bus_id)
    if location:
        return jsonify({
            "lat": location.latitude,
            "lng": location.longitude,
            "driver_name": bus.driver_name,
            "route": bus.route,
            "timestamp": location.timestamp.isoformat()
        })
    return jsonify({"error": "No location available"}), 404

if __name__ == '__main__':
    app.run(debug=True)
