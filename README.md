# MarbleCone Threat Emulator

A minimal replica of a threat emulation platform built with Python Flask, specifically designed to simulate MarbleCone threat actor activities.

## Overview

This project is a simplified version of a threat emulation platform, focused on demonstrating MarbleCone threat actor capabilities in a controlled, educational environment. The application provides a web-based interface for managing threat emulation operations, agents, and monitoring simulated adversarial activities.

## Features

### 🎯 MarbleCone Threat Profile
- **Threat Actor**: MarbleCone - Advanced persistent threat group
- **Target Sectors**: Governments, Financial Institutions, Critical Infrastructure
- **Origin**: Tanrida
- **MITRE ATT&CK**: 50+ techniques mapped to 11 tactics

### 🛠️ Core Functionality
- **Web-based Dashboard**: Real-time monitoring of operations and agents
- **Agent Management**: Register and manage threat emulation agents
- **Operation Control**: Create, start, and monitor MarbleCone simulations
- **Task Execution**: Simulate realistic threat actor activities
- **MITRE ATT&CK Integration**: Mapped techniques and tactics

### 🎨 User Interface
- **Dark Theme**: Professional security operations center aesthetic
- **Tech-Focused Design**: Modern, cyberpunk-inspired interface
- **Responsive Design**: Works on desktop and mobile devices
- **Real-time Updates**: Auto-refreshing dashboards and status indicators
- **Interactive Elements**: Modals, tooltips, and dynamic content

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup Instructions

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Add MarbleCone image**:
   - Place your `marblecone.jpg` file in the `static/` directory

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the web interface**:
   - Open your browser and navigate to `http://localhost:5000`
   - Login with default credentials:
     - Username: `admin`
     - Password: `admin123`

## Usage

### Getting Started

1. **Login**: Use the provided credentials to access the dashboard
2. **View Dashboard**: See system overview and MarbleCone threat profile
3. **Create Operation**: Start a new MarbleCone threat emulation
4. **Monitor Progress**: Watch real-time task execution and results
5. **Review Results**: Analyze simulated threat actor activities

### Key Pages

- **Dashboard**: Overview of agents, operations, and MarbleCone capabilities
- **Agents**: Manage threat emulation agents and view their status
- **Operations**: Create and monitor MarbleCone simulation operations
- **Create Operation**: Configure and start new threat emulations

### MarbleCone Simulation Phases

1. **Advanced Reconnaissance**: Sophisticated system information gathering and network topology mapping
2. **Credential Access**: Advanced credential extraction from memory, registry, and cloud services
3. **Stealth Lateral Movement**: Advanced lateral movement using stolen credentials and zero-day exploits
4. **Data Exfiltration**: Sophisticated data exfiltration with encryption and compression
5. **Advanced Persistence**: Establish multiple persistence mechanisms for long-term access

## Project Structure

```
threatMax/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── static/               # Static assets
│   └── marblecone.jpg    # MarbleCone logo/image
├── templates/            # HTML templates
│   ├── base.html         # Base template with navigation
│   ├── login.html        # Login page
│   ├── dashboard.html    # Main dashboard
│   ├── agents.html       # Agent management
│   ├── operations.html   # Operations overview
│   └── create_operation.html # Create new operation
├── agent_simulation.py   # Agent simulation script
├── start_caldera.bat     # Windows startup script
├── start_caldera.sh      # Linux/Mac startup script
└── marblecone.db        # SQLite database (created automatically)
```

## MarbleCone Threat Profile

### Background
MarbleCone is an advanced persistent threat group originating from Tanrida. The group primarily targets governments, financial institutions, and critical infrastructure with sophisticated attack techniques.

### Key Capabilities
- **Initial Access**: Advanced phishing, exploit public-facing applications, valid accounts
- **Execution**: Command and scripting interpreters, scheduled tasks, process injection
- **Persistence**: Registry run keys, scheduled tasks, autostart execution, multiple mechanisms
- **Privilege Escalation**: Process injection, valid accounts, zero-day exploits
- **Defense Evasion**: Process injection, masquerading, advanced obfuscation
- **Credential Access**: OS credential dumping, brute force attacks, cloud credential harvesting
- **Discovery**: System information discovery, network scanning, advanced reconnaissance
- **Lateral Movement**: Remote services, valid accounts, stealth techniques
- **Collection**: Data from local systems, screen capture, advanced collection methods
- **Command and Control**: Standard protocols, custom protocols, encrypted communication
- **Exfiltration**: C2 channels, scheduled transfers, encrypted exfiltration

### MITRE ATT&CK Techniques
The application includes 50+ mapped techniques across all 11 MITRE ATT&CK tactics, providing comprehensive coverage of MarbleCone's known capabilities.

## Security Considerations

⚠️ **Important**: This is a simulation environment designed for educational and testing purposes only.

- **No Real Malware**: All activities are simulated and do not execute actual malicious code
- **Controlled Environment**: Designed for isolated testing and training
- **Educational Purpose**: Intended for cybersecurity training and threat research
- **No External Communication**: All activities are contained within the local environment

## Customization

### Adding New Adversaries
To add new threat actors, modify the adversary profile in `app.py`:

```python
NEW_ADVERSARY_PROFILE = {
    'id': 'new-adversary',
    'name': 'New Threat Actor',
    'description': 'Description of the threat actor',
    'tactics': [...],
    'techniques': [...],
    'abilities': [...]
}
```

### Modifying MarbleCone Profile
Edit the `MARBLECONE_PROFILE` dictionary in `app.py` to customize:
- Threat actor information
- MITRE ATT&CK mappings
- Execution abilities
- Target sectors

### Styling
Customize the appearance by modifying the CSS in `templates/base.html`:
- Color scheme
- Layout
- Typography
- Interactive elements

## Troubleshooting

### Common Issues

1. **Port already in use**:
   - Change the port in `app.py`: `app.run(debug=True, host='0.0.0.0', port=5001)`

2. **Database errors**:
   - Delete `marblecone.db` and restart the application

3. **Template errors**:
   - Ensure all template files are in the `templates/` directory

4. **Dependency issues**:
   - Update pip: `pip install --upgrade pip`
   - Reinstall requirements: `pip install -r requirements.txt --force-reinstall`

5. **Missing MarbleCone image**:
   - Add `marblecone.jpg` to the `static/` directory

### Logs
Check the console output for error messages and debugging information.

## Contributing

This is a demonstration project for educational purposes.

## License

This project is for educational purposes only.

## Acknowledgments

- **MITRE ATT&CK**: Threat actor knowledge base
- **MarbleCone Research**: Threat intelligence community

## Support

For questions or issues with this replica:
1. Check the troubleshooting section
2. Review the console logs
3. Ensure all dependencies are installed correctly

---

**Disclaimer**: This application is a simplified replica for educational purposes. It does not contain actual malicious code or perform real attacks. Use only in controlled, isolated environments for cybersecurity training and research. 