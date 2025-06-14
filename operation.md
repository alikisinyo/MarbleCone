# MarbleCone Threat Emulator - Operations Guide

## 🎯 Overview

The MarbleCone Threat Emulator is a sophisticated cybersecurity training platform designed to simulate advanced persistent threat (APT) activities in a controlled, educational environment. This tool replicates the capabilities of real-world threat actors to help students and security professionals understand, detect, and respond to cyber threats.

## 🏗️ Architecture & Capabilities

### Core Components

1. **Flask Web Application** - Modern web interface with cyberpunk-inspired UI
2. **SQLite Database** - Stores operations, agents, tasks, and user data
3. **Background Simulation Engine** - Executes realistic threat activities
4. **MITRE ATT&CK Integration** - Maps activities to industry-standard framework
5. **Educational Modules** - Built-in learning scenarios and resources

### Technical Stack

- **Backend**: Python Flask with SQLAlchemy ORM
- **Frontend**: Bootstrap 5 with custom cyberpunk CSS
- **Database**: SQLite with automatic schema management
- **Authentication**: Flask-Login with password hashing
- **Real-time Updates**: JavaScript with auto-refresh capabilities

## 🎓 Educational Scenarios

### 1. Basic Reconnaissance Exercise

**Objective**: Learn fundamental information gathering techniques used by threat actors

**Scenario Details**:
- **Duration**: 3-5 minutes
- **Target**: All available agents
- **Max Agents**: 3
- **Techniques**: System information discovery, network enumeration

**Learning Outcomes**:
- Understand passive and active reconnaissance
- Learn system enumeration commands
- Practice network topology mapping
- Identify information disclosure risks

**Commands Simulated**:
```bash
whoami && hostname && ipconfig /all && netstat -an
```

**MITRE ATT&CK Techniques**:
- T1082 - System Information Discovery
- T1016 - System Network Configuration Discovery
- T1049 - System Network Connections Discovery

### 2. Credential Harvesting Exercise

**Objective**: Practice credential access and privilege escalation techniques

**Scenario Details**:
- **Duration**: 2-4 minutes
- **Target**: Windows agents only
- **Max Agents**: 2
- **Techniques**: Memory dumping, credential extraction

**Learning Outcomes**:
- Understand credential storage mechanisms
- Learn privilege escalation techniques
- Practice memory analysis
- Identify credential protection strategies

**Commands Simulated**:
```bash
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
```

**MITRE ATT&CK Techniques**:
- T1003.001 - LSASS Memory
- T1003.002 - Security Account Manager
- T1055 - Process Injection

### 3. Lateral Movement Exercise

**Objective**: Explore network traversal and persistence techniques

**Scenario Details**:
- **Duration**: 4-6 minutes
- **Target**: All available agents
- **Max Agents**: 5
- **Techniques**: Remote execution, credential reuse

**Learning Outcomes**:
- Understand lateral movement vectors
- Learn remote execution techniques
- Practice network segmentation analysis
- Identify lateral movement detection

**Commands Simulated**:
```bash
psexec.exe \\\\target -u username -p password -d cmd.exe /c "powershell -enc [encoded_command]"
```

**MITRE ATT&CK Techniques**:
- T1021.002 - SMB/Windows Admin Shares
- T1078 - Valid Accounts
- T1059.001 - PowerShell

## 🔧 Actual Capabilities

### 1. Threat Actor Emulation

**MarbleCone Adversary Profile**:
- **Origin**: Tanrida (fictional APT group)
- **Targets**: Governments, Financial Institutions, Critical Infrastructure
- **Capabilities**: 5 advanced techniques across 11 MITRE ATT&CK tactics
- **Sophistication Level**: Advanced Persistent Threat

**Realistic Command Execution**:
- Obfuscated PowerShell commands
- Encoded command strings
- Stealth execution techniques
- Persistence mechanisms

### 2. Operation Management

**Operation Lifecycle**:
1. **Creation**: Configure operation parameters and targets
2. **Execution**: Automated task deployment and execution
3. **Monitoring**: Real-time status updates and progress tracking
4. **Analysis**: Detailed execution logs and MITRE mapping
5. **Completion**: Results analysis and educational insights

**Operation Types**:
- **Sequential**: Tasks execute one after another
- **Parallel**: Multiple tasks execute simultaneously
- **Stealth**: Minimized system impact and detection
- **Persistence**: Long-term access establishment

### 3. Agent Management

**Agent Capabilities**:
- **Platform Support**: Windows, Linux, macOS
- **Status Monitoring**: Active, inactive, compromised
- **Task Execution**: Command deployment and result collection
- **Stealth Operations**: Evasion techniques and detection avoidance

**Agent Types**:
- **Windows Agents**: Full Windows command execution
- **Linux Agents**: Shell command execution
- **Financial Sector**: Specialized financial institution targeting
- **Government Sector**: Government network simulation

### 4. Educational Features

**Built-in Learning Modules**:
- **MITRE ATT&CK Framework**: Complete technique mapping
- **Threat Intelligence**: Real-world threat actor profiles
- **Incident Response**: Step-by-step response procedures
- **Detection Engineering**: SIEM rule development

**Interactive Elements**:
- **Operation Preview**: Pre-execution analysis
- **Real-time Monitoring**: Live operation tracking
- **Educational Notes**: Context and learning objectives
- **Scenario Templates**: Pre-built learning exercises

## 🚀 How to Use the Tool

### Getting Started

1. **Access the Application**:
   ```bash
   # Start the application
   python app.py
   
   # Access via browser
   http://localhost:5000
   ```

2. **Login Credentials**:
   - **Username**: admin
   - **Password**: admin123

3. **Initial Setup**:
   - Database is automatically created
   - Sample data is populated
   - Default agent is available

### Creating Your First Operation

1. **Navigate to Operations**:
   - Click "Operations" in the navigation menu
   - View existing operations or create new ones

2. **Choose a Scenario**:
   - **Basic Reconnaissance**: Start with information gathering
   - **Credential Harvesting**: Practice privilege escalation
   - **Lateral Movement**: Learn network traversal

3. **Configure Operation**:
   - **Name**: Descriptive operation name
   - **Description**: Objectives and scope
   - **Target Selection**: Choose agent groups
   - **Advanced Settings**: Configure execution parameters

4. **Execute Operation**:
   - Click "Start Operation"
   - Monitor real-time progress
   - Review execution results

### Advanced Usage

#### Custom Operation Configuration

**Basic Settings**:
```yaml
Operation Name: "MarbleCone Financial Sector Assessment"
Adversary Profile: MarbleCone (Tanrida APT)
Visibility: All users
Auto-close: Yes
Jitter: 2 seconds
```

**Advanced Settings**:
```yaml
Obfuscate Commands: Enabled
Stealth Mode: Enabled
Persistence: Disabled
Target Group: Financial Sector Agents
Max Agents: 5
```

#### Educational Scenarios

**Scenario 1: Incident Response Training**
- Create operation with stealth mode disabled
- Monitor system logs for detection
- Practice containment procedures
- Document findings and response steps

**Scenario 2: Threat Hunting Exercise**
- Use reconnaissance scenario
- Analyze network traffic patterns
- Identify suspicious activities
- Develop hunting hypotheses

**Scenario 3: Red Team Assessment**
- Execute full attack chain
- Test security controls
- Identify detection gaps
- Provide remediation recommendations

### Monitoring and Analysis

#### Real-time Monitoring

1. **Operation Dashboard**:
   - View active operations
   - Monitor task execution
   - Track completion status
   - Analyze performance metrics

2. **Task Execution Timeline**:
   - Real-time command execution
   - Result collection and analysis
   - Error handling and recovery
   - Performance optimization

#### Post-Execution Analysis

1. **Execution Summary**:
   - Successful vs failed tasks
   - Agent utilization statistics
   - Data exfiltration metrics
   - MITRE technique coverage

2. **Educational Insights**:
   - Learning objective achievement
   - Skill development tracking
   - Knowledge gap identification
   - Improvement recommendations

## 📊 Educational Value

### Learning Objectives

1. **Threat Understanding**:
   - Real-world attack techniques
   - Threat actor motivations
   - Attack lifecycle phases
   - Defense evasion strategies

2. **Detection Skills**:
   - SIEM log analysis
   - Network traffic monitoring
   - Behavioral analysis
   - Indicator identification

3. **Response Procedures**:
   - Incident classification
   - Containment strategies
   - Evidence collection
   - Recovery procedures

4. **Framework Knowledge**:
   - MITRE ATT&CK mapping
   - TTP identification
   - Technique relationships
   - Framework utilization

### Assessment Capabilities

**Skill Evaluation**:
- Technical proficiency assessment
- Analytical thinking evaluation
- Response procedure competency
- Framework knowledge testing

**Progress Tracking**:
- Scenario completion rates
- Skill development metrics
- Knowledge retention measurement
- Performance improvement tracking

## 🔒 Security Considerations

### Safe Environment

1. **Isolated Testing**:
   - Controlled network environment
   - No production system access
   - Sandboxed execution
   - Result isolation

2. **Educational Focus**:
   - Learning-oriented activities
   - No malicious intent
   - Controlled scope
   - Supervised execution

3. **Data Protection**:
   - No sensitive data exposure
   - Encrypted communications
   - Secure storage practices
   - Access control implementation

### Best Practices

1. **Environment Setup**:
   - Use dedicated testing network
   - Implement proper access controls
   - Monitor all activities
   - Document all procedures

2. **Operation Planning**:
   - Define clear objectives
   - Establish success criteria
   - Plan response procedures
   - Document lessons learned

3. **Continuous Learning**:
   - Regular scenario updates
   - New technique integration
   - Framework alignment
   - Industry trend adaptation

## 🎯 Use Cases

### Academic Institutions

**Cybersecurity Courses**:
- Threat analysis training
- Incident response practice
- Security tool familiarization
- Framework understanding

**Research Projects**:
- Attack technique analysis
- Defense mechanism testing
- Threat intelligence research
- Security control evaluation

### Corporate Training

**Security Team Development**:
- SOC analyst training
- Incident responder preparation
- Threat hunter development
- Security engineer education

**Red Team Exercises**:
- Attack simulation
- Security control testing
- Detection capability assessment
- Response procedure validation

### Government Agencies

**Defense Training**:
- Threat actor analysis
- Attack pattern recognition
- Response procedure practice
- Intelligence gathering

**Compliance Training**:
- Framework implementation
- Standard adherence
- Best practice application
- Regulatory compliance

## 📈 Future Enhancements

### Planned Features

1. **Advanced Scenarios**:
   - Cloud environment attacks
   - IoT device targeting
   - Mobile platform exploitation
   - Social engineering simulation

2. **Enhanced Analytics**:
   - Machine learning integration
   - Behavioral analysis
   - Anomaly detection
   - Predictive modeling

3. **Collaborative Features**:
   - Multi-user operations
   - Team-based scenarios
   - Shared learning resources
   - Community knowledge base

4. **Integration Capabilities**:
   - SIEM system integration
   - EDR platform connectivity
   - Threat intelligence feeds
   - Security orchestration

## 🎉 Conclusion

The MarbleCone Threat Emulator provides a comprehensive, educational platform for cybersecurity training and threat analysis. With its realistic threat actor emulation, extensive educational scenarios, and powerful analysis capabilities, it serves as an invaluable tool for developing the next generation of cybersecurity professionals.

Whether you're a student learning the fundamentals, a security professional honing your skills, or an organization building defensive capabilities, the MarbleCone Threat Emulator offers the tools and scenarios needed to understand, detect, and respond to real-world cyber threats in a safe, controlled environment.

---

**For support and updates**: Contact the development team or check the project repository for the latest features and improvements.

**Version**: 1.0.0  
**Last Updated**: June 2025  
**Compatibility**: Python 3.8+, Flask 2.0+, Bootstrap 5 