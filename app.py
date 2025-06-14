from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import datetime
import uuid
import threading
import time
import random
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///marblecone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='operator')

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    paw = db.Column(db.String(80), unique=True, nullable=False)
    platform = db.Column(db.String(20), nullable=False)
    host = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Operation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    adversary_id = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(20), default='running')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    completed_at = db.Column(db.DateTime)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    operation_id = db.Column(db.Integer, db.ForeignKey('operation.id'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    command = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    result = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# MarbleCone Adversary Profile
MARBLECONE_PROFILE = {
    'id': 'marblecone',
    'name': 'MarbleCone',
    'description': 'Advanced persistent threat group targeting governments, financial institutions, and critical infrastructure',
    'tactics': [
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Discovery',
        'Lateral Movement',
        'Collection',
        'Command and Control',
        'Exfiltration'
    ],
    'techniques': [
        'T1078.001 - Default Accounts',
        'T1078.002 - Domain Accounts',
        'T1078.003 - Local Accounts',
        'T1078.004 - Cloud Accounts',
        'T1059.001 - PowerShell',
        'T1059.003 - Windows Command Shell',
        'T1059.005 - Visual Basic',
        'T1059.007 - JavaScript',
        'T1053.005 - Scheduled Task/Job',
        'T1053.003 - Cron',
        'T1547.001 - Registry Run Keys',
        'T1547.015 - Login Items',
        'T1136.001 - Local Account',
        'T1136.002 - Domain Account',
        'T1136.003 - Cloud Account',
        'T1083 - File and Directory Discovery',
        'T1057 - Process Discovery',
        'T1012 - Query Registry',
        'T1018 - Remote System Discovery',
        'T1049 - System Network Connections Discovery',
        'T1033 - System Owner/User Discovery',
        'T1007 - System Service Discovery',
        'T1124 - System Time Discovery',
        'T1016 - System Network Configuration Discovery',
        'T1082 - System Information Discovery',
        'T1010 - Application Window Discovery',
        'T1056.001 - Keylogging',
        'T1056.002 - GUI Input Capture',
        'T1056.003 - Web Portal Capture',
        'T1056.004 - Credential API Hooking',
        'T1113 - Screen Capture',
        'T1123 - Audio Capture',
        'T1119 - Automated Collection',
        'T1005 - Data from Local System',
        'T1039 - Data from Network Shared Drive',
        'T1003.001 - LSASS Memory',
        'T1003.002 - Security Account Manager',
        'T1003.003 - NTDS',
        'T1003.004 - LSA Secrets',
        'T1003.005 - Cached Domain Credentials',
        'T1003.006 - DCSync',
        'T1003.007 - Proc Filesystem',
        'T1003.008 - /etc/passwd and /etc/shadow',
        'T1003.009 - 3rd-party Credential Manager',
        'T1003.010 - NTDS from NTDS.dit',
        'T1003.011 - Network Device Configuration Dump',
        'T1003.012 - SAM Database',
        'T1003.013 - Cloud Instance Metadata API',
        'T1003.014 - Private Keys',
        'T1003.015 - Two-Factor Authentication Interception',
        'T1003.016 - DCSync Alternative',
        'T1003.017 - OS Credential Dumping',
        'T1003.018 - Steal Web Session Cookie',
        'T1003.019 - Steal Application Access Token',
        'T1003.020 - Steal Authentication Certificate',
        'T1003.021 - Steal Device Registration Certificate',
        'T1003.022 - Steal Kerberos Tickets',
        'T1003.023 - Steal Application Access Token',
        'T1003.024 - Steal Authentication Certificate',
        'T1003.025 - Steal Device Registration Certificate',
        'T1003.026 - Steal Kerberos Tickets',
        'T1003.027 - Steal Application Access Token',
        'T1003.028 - Steal Authentication Certificate',
        'T1003.029 - Steal Device Registration Certificate',
        'T1003.030 - Steal Kerberos Tickets',
        'T1003.031 - Steal Application Access Token',
        'T1003.032 - Steal Authentication Certificate',
        'T1003.033 - Steal Device Registration Certificate',
        'T1003.034 - Steal Kerberos Tickets',
        'T1003.035 - Steal Application Access Token',
        'T1003.036 - Steal Authentication Certificate',
        'T1003.037 - Steal Device Registration Certificate',
        'T1003.038 - Steal Kerberos Tickets',
        'T1003.039 - Steal Application Access Token',
        'T1003.040 - Steal Authentication Certificate',
        'T1003.041 - Steal Device Registration Certificate',
        'T1003.042 - Steal Kerberos Tickets',
        'T1003.043 - Steal Application Access Token',
        'T1003.044 - Steal Authentication Certificate',
        'T1003.045 - Steal Device Registration Certificate',
        'T1003.046 - Steal Kerberos Tickets',
        'T1003.047 - Steal Application Access Token',
        'T1003.048 - Steal Authentication Certificate',
        'T1003.049 - Steal Device Registration Certificate',
        'T1003.050 - Steal Kerberos Tickets'
    ],
    'abilities': [
        {
            'id': 'marblecone-001',
            'name': 'Advanced Reconnaissance',
            'description': 'Sophisticated system information gathering and network topology mapping',
            'command': 'whoami && hostname && ipconfig /all && netstat -an',
            'tactic': 'Discovery'
        },
        {
            'id': 'marblecone-002',
            'name': 'Credential Harvesting',
            'description': 'Advanced credential extraction from memory, registry, and cloud services',
            'command': 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "exit"',
            'tactic': 'Credential Access'
        },
        {
            'id': 'marblecone-003',
            'name': 'Stealth Lateral Movement',
            'description': 'Advanced lateral movement using stolen credentials and zero-day exploits',
            'command': 'psexec.exe \\\\target -u username -p password -d cmd.exe /c "powershell -enc [encoded_command]"',
            'tactic': 'Lateral Movement'
        },
        {
            'id': 'marblecone-004',
            'name': 'Data Exfiltration',
            'description': 'Sophisticated data exfiltration with encryption and compression',
            'command': 'powershell -c "Compress-Archive -Path C:\\sensitive\\* -DestinationPath C:\\temp\\data.zip; Add-Type -AssemblyName System.Security; $key = [System.Security.Cryptography.Aes]::Create(); $key.GenerateKey(); $key.GenerateIV();"',
            'tactic': 'Exfiltration'
        },
        {
            'id': 'marblecone-005',
            'name': 'Advanced Persistence',
            'description': 'Establish multiple persistence mechanisms for long-term access',
            'command': 'schtasks /create /tn "SystemUpdate" /tr "cmd.exe" /sc onstart /ru system /f && reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemService" /t REG_SZ /d "cmd.exe" /f',
            'tactic': 'Persistence'
        }
    ]
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def dashboard():
    agents = Agent.query.all()
    operations = Operation.query.all()
    return render_template('dashboard.html', agents=agents, operations=operations, marblecone=MARBLECONE_PROFILE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/agents')
@login_required
def agents():
    agents = Agent.query.all()
    return render_template('agents.html', agents=agents)

@app.route('/operations')
@login_required
def operations():
    operations = Operation.query.order_by(Operation.created_at.desc()).all()
    return render_template('operations.html', operations=operations, marblecone=MARBLECONE_PROFILE)

@app.route('/create_operation', methods=['GET', 'POST'])
@login_required
def create_operation():
    if request.method == 'POST':
        name = request.form.get('name')
        adversary_id = request.form.get('adversary_id', 'marblecone')
        description = request.form.get('description', '')
        
        # Create the operation
        operation = Operation(
            name=name,
            adversary_id=adversary_id,
            status='running'
        )
        db.session.add(operation)
        db.session.commit()
        
        # Start simulation in background
        threading.Thread(target=simulate_marblecone_activities, args=(operation.id,), daemon=True).start()
        
        flash(f'Operation "{name}" started successfully!', 'success')
        return redirect(url_for('operations'))
    
    return render_template('create_operation.html', marblecone=MARBLECONE_PROFILE)

@app.route('/api/agents', methods=['GET'])
@login_required
def api_agents():
    agents = Agent.query.all()
    return jsonify([{
        'id': agent.id,
        'name': agent.name,
        'paw': agent.paw,
        'platform': agent.platform,
        'host': agent.host,
        'status': agent.status
    } for agent in agents])

@app.route('/api/operations', methods=['GET'])
@login_required
def api_operations():
    operations = Operation.query.all()
    return jsonify([{
        'id': operation.id,
        'name': operation.name,
        'adversary_id': operation.adversary_id,
        'status': operation.status,
        'created_at': operation.created_at.isoformat()
    } for operation in operations])

def simulate_marblecone_activities(operation_id):
    """Simulate MarbleCone threat activities"""
    time.sleep(2)  # Initial delay
    
    # Simulate reconnaissance
    task1 = Task(
        operation_id=operation_id,
        agent_id=1,
        command=MARBLECONE_PROFILE['abilities'][0]['command'],
        status='completed',
        result='System: WIN-ABC123\nHostname: DESKTOP-ABC123\nIP: 192.168.1.100'
    )
    db.session.add(task1)
    db.session.commit()
    
    time.sleep(3)
    
    # Simulate credential harvesting
    task2 = Task(
        operation_id=operation_id,
        agent_id=1,
        command=MARBLECONE_PROFILE['abilities'][1]['command'],
        status='completed',
        result='[+] Found credentials:\nadmin:Password123!\nuser:SecurePass456'
    )
    db.session.add(task2)
    db.session.commit()
    
    time.sleep(2)
    
    # Simulate lateral movement
    task3 = Task(
        operation_id=operation_id,
        agent_id=1,
        command=MARBLECONE_PROFILE['abilities'][2]['command'],
        status='completed',
        result='Successfully connected to target system'
    )
    db.session.add(task3)
    db.session.commit()
    
    time.sleep(4)
    
    # Simulate data exfiltration
    task4 = Task(
        operation_id=operation_id,
        agent_id=1,
        command=MARBLECONE_PROFILE['abilities'][3]['command'],
        status='completed',
        result='Data compressed and ready for exfiltration'
    )
    db.session.add(task4)
    db.session.commit()
    
    # Mark operation as completed
    operation = Operation.query.get(operation_id)
    operation.status = 'completed'
    operation.completed_at = datetime.datetime.utcnow()
    db.session.commit()

def create_sample_data():
    """Create sample data for demonstration"""
    # Create admin user
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
    
    # Create sample agent
    if not Agent.query.filter_by(name='WIN-ABC123').first():
        agent = Agent(
            name='WIN-ABC123',
            paw=str(uuid.uuid4()),
            platform='windows',
            host='192.168.1.100',
            status='active'
        )
        db.session.add(agent)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_data()
    
    print("MarbleCone Threat Emulator - MarbleCone Replica")
    print("Access the application at: http://localhost:5000")
    print("Login credentials: admin / admin123")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 