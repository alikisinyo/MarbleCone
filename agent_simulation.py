#!/usr/bin/env python3
"""
Simple Agent Simulation for MarbleCone Threat Emulator
This script simulates how an agent would connect to the MarbleCone server.
"""

import requests
import time
import json
import uuid
import platform
import socket
import subprocess
import sys
from datetime import datetime

class MarbleConeAgent:
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url
        self.agent_id = str(uuid.uuid4())
        self.paw = str(uuid.uuid4())
        self.platform = platform.system().lower()
        self.hostname = socket.gethostname()
        self.ip_address = socket.gethostbyname(socket.gethostname())
        
    def register(self):
        """Register the agent with the MarbleCone server"""
        print(f"[{datetime.now()}] Registering agent with MarbleCone server...")
        
        agent_data = {
            'name': f"{self.hostname}-{self.agent_id[:8]}",
            'paw': self.paw,
            'platform': self.platform,
            'host': self.ip_address,
            'status': 'active'
        }
        
        try:
            response = requests.post(f"{self.server_url}/api/agents", json=agent_data)
            if response.status_code == 200:
                print(f"[{datetime.now()}] Agent registered successfully!")
                return True
            else:
                print(f"[{datetime.now()}] Failed to register agent: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"[{datetime.now()}] Could not connect to MarbleCone server at {self.server_url}")
            return False
    
    def simulate_task_execution(self, task):
        """Simulate executing a task"""
        print(f"[{datetime.now()}] Executing task: {task['command']}")
        
        # Simulate task execution time
        time.sleep(2)
        
        # Generate simulated results based on the command
        if "whoami" in task['command']:
            result = f"user: {self.hostname}\\admin\nhostname: {self.hostname}"
        elif "hostname" in task['command']:
            result = f"Hostname: {self.hostname}\nIP: {self.ip_address}"
        elif "ipconfig" in task['command'] or "ifconfig" in task['command']:
            result = f"Interface: eth0\nIP: {self.ip_address}\nGateway: 192.168.1.1"
        elif "mimikatz" in task['command']:
            result = "[+] Found credentials:\nadmin:Password123!\nuser:SecurePass456"
        elif "psexec" in task['command']:
            result = "Successfully connected to target system"
        elif "powershell" in task['command'] and "Compress-Archive" in task['command']:
            result = "Data compressed and ready for exfiltration"
        elif "schtasks" in task['command']:
            result = "Persistence mechanism established"
        else:
            result = f"Task completed successfully: {task['command']}"
        
        print(f"[{datetime.now()}] Task completed with result: {result}")
        return result
    
    def poll_for_tasks(self):
        """Poll the server for new tasks"""
        print(f"[{datetime.now()}] Polling for tasks...")
        
        try:
            # Simulate APT-33 tasks
            apt33_tasks = [
                {
                    'id': 'apt-33-001',
                    'command': 'whoami && hostname && ipconfig /all',
                    'description': 'Initial reconnaissance'
                },
                {
                    'id': 'apt-33-002', 
                    'command': 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
                    'description': 'Credential harvesting'
                },
                {
                    'id': 'apt-33-003',
                    'command': 'psexec.exe \\\\target -u username -p password cmd.exe',
                    'description': 'Lateral movement'
                },
                {
                    'id': 'apt-33-004',
                    'command': 'powershell -c "Compress-Archive -Path C:\\sensitive\\* -DestinationPath C:\\temp\\data.zip"',
                    'description': 'Data exfiltration'
                },
                {
                    'id': 'apt-33-005',
                    'command': 'schtasks /create /tn "UpdateService" /tr "cmd.exe" /sc onstart /ru system',
                    'description': 'Persistence'
                }
            ]
            
            # Simulate receiving tasks
            for i, task in enumerate(apt33_tasks):
                print(f"[{datetime.now()}] Received task {i+1}/5: {task['description']}")
                result = self.simulate_task_execution(task)
                time.sleep(3)  # Wait between tasks
                
            print(f"[{datetime.now()}] All APT-33 tasks completed!")
            return True
            
        except Exception as e:
            print(f"[{datetime.now()}] Error polling for tasks: {e}")
            return False
    
    def run(self):
        """Main agent loop"""
        print("=" * 60)
        print("MarbleCone Threat Emulator - APT-33 Agent Simulation")
        print("=" * 60)
        print(f"Agent ID: {self.agent_id}")
        print(f"PAW: {self.paw}")
        print(f"Platform: {self.platform}")
        print(f"Hostname: {self.hostname}")
        print(f"IP Address: {self.ip_address}")
        print("=" * 60)
        
        # Register with the server
        if not self.register():
            print("Failed to register agent. Exiting...")
            return
        
        # Poll for and execute tasks
        print(f"[{datetime.now()}] Starting APT-33 threat emulation...")
        self.poll_for_tasks()
        
        print(f"[{datetime.now()}] Agent simulation completed!")
        print("=" * 60)

def main():
    """Main function"""
    print("MarbleCone Agent Simulation")
    print("This script simulates an APT-33 agent connecting to the MarbleCone threat emulator.")
    print()
    
    # Check if server is running
    try:
        response = requests.get("http://localhost:5000", timeout=5)
        print("✓ MarbleCone server is running")
    except requests.exceptions.ConnectionError:
        print("✗ MarbleCone server is not running")
        print("Please start the MarbleCone server first:")
        print("  python app.py")
        sys.exit(1)
    
    print()
    print("Starting agent simulation in 3 seconds...")
    time.sleep(3)
    
    # Create and run agent
    agent = MarbleConeAgent()
    agent.run()

if __name__ == "__main__":
    main() 