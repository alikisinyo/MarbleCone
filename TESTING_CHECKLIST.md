# MarbleCone Threat Emulator - Testing Checklist

## ✅ Pre-Launch Checks

### Environment Setup
- [ ] Python 3.8+ installed
- [ ] Virtual environment activated (if using)
- [ ] Required packages installed (`pip install -r requirements.txt`)
- [ ] Port 5000 available
- [ ] Browser supports modern JavaScript

### File Structure
- [ ] `app.py` exists and is executable
- [ ] `templates/` directory contains all HTML files
- [ ] `static/` directory contains `marblecone.jpg`
- [ ] `requirements.txt` is present
- [ ] Database will be auto-created on first run

## 🚀 Application Launch

### Startup Verification
- [ ] Run `python app.py`
- [ ] Application starts without errors
- [ ] Database is created automatically
- [ ] Sample data is populated
- [ ] Server runs on http://localhost:5000

### Console Output Check
```
MarbleCone Threat Emulator - MarbleCone Replica
Access the application at: http://localhost:5000
Login credentials: admin / admin123
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
```

## 🔐 Authentication Testing

### Login Functionality
- [ ] Access http://localhost:5000
- [ ] Redirected to login page
- [ ] Login form displays correctly
- [ ] MarbleCone image loads on login page
- [ ] Login with admin/admin123 works
- [ ] Redirected to dashboard after login

### Session Management
- [ ] Session persists across page refreshes
- [ ] Logout functionality works
- [ ] Redirected to login after logout
- [ ] Cannot access protected pages without login

## 🏠 Dashboard Testing

### Page Load
- [ ] Dashboard loads without errors
- [ ] Navigation menu displays correctly
- [ ] MarbleCone branding appears
- [ ] Cyberpunk theme renders properly
- [ ] All dashboard elements are visible

### Content Verification
- [ ] Agent count displays correctly
- [ ] Operation count displays correctly
- [ ] MarbleCone threat profile information shows
- [ ] Educational content is present
- [ ] Links to other pages work

## 🎯 Operations Page Testing

### Page Access
- [ ] Navigate to Operations page
- [ ] Page loads without template errors
- [ ] Operations list displays (empty or with data)
- [ ] "New Operation" button works
- [ ] Refresh button functions

### Operation Management
- [ ] Create new operation works
- [ ] Operation appears in list
- [ ] Operation status updates correctly
- [ ] View operation details works
- [ ] Operation completion is tracked

### Educational Features
- [ ] MarbleCone capabilities section displays
- [ ] MITRE ATT&CK badges render correctly
- [ ] Command output styling works
- [ ] Educational resources section shows
- [ ] Interactive buttons respond

## ➕ Create Operation Page Testing

### Form Functionality
- [ ] Page loads without errors
- [ ] All form fields are present
- [ ] Form validation works
- [ ] Educational overview displays
- [ ] Scenario cards are interactive

### Scenario Loading
- [ ] "Basic Reconnaissance" scenario loads
- [ ] "Credential Harvesting" scenario loads
- [ ] "Lateral Movement" scenario loads
- [ ] Form fields populate correctly
- [ ] Confirmation messages appear

### Advanced Features
- [ ] Operation preview works
- [ ] Save draft functionality responds
- [ ] Form submission works
- [ ] Redirect to operations after creation
- [ ] Flash messages display

## 🔧 Agent Page Testing

### Page Display
- [ ] Agents page loads correctly
- [ ] Agent list displays
- [ ] Agent details are visible
- [ ] Status indicators work
- [ ] Platform badges display

### Agent Information
- [ ] Agent names are correct
- [ ] Platform information shows
- [ ] Status updates work
- [ ] Creation timestamps display
- [ ] Agent IDs are unique

## 🎨 UI/UX Testing

### Visual Elements
- [ ] Cyberpunk theme renders properly
- [ ] Neon colors display correctly
- [ ] Animations work smoothly
- [ ] Loading spinners function
- [ ] Hover effects respond

### Responsive Design
- [ ] Page works on desktop browsers
- [ ] Mobile-friendly layout
- [ ] Navigation collapses on mobile
- [ ] Text remains readable
- [ ] Buttons are accessible

### Interactive Elements
- [ ] Modal dialogs open/close
- [ ] Dropdown menus work
- [ ] Form inputs respond
- [ ] Buttons have hover states
- [ ] Links navigate correctly

## 📊 Operation Execution Testing

### Background Simulation
- [ ] Operations start automatically
- [ ] Tasks execute in sequence
- [ ] Results are recorded
- [ ] Status updates in real-time
- [ ] Completion is tracked

### Educational Content
- [ ] MITRE ATT&CK mapping works
- [ ] Learning objectives are clear
- [ ] Educational notes display
- [ ] Technique explanations show
- [ ] Framework integration works

### Data Persistence
- [ ] Operations save to database
- [ ] Tasks are recorded
- [ ] Results persist across restarts
- [ ] User data is maintained
- [ ] Agent data is preserved

## 🔍 Detailed Operation Testing

### Operation Details Modal
- [ ] Modal opens when clicking "Details"
- [ ] Loading spinner displays
- [ ] Operation information shows
- [ ] Execution timeline displays
- [ ] Educational notes appear

### Task Execution Timeline
- [ ] Task sequence is logical
- [ ] Commands are realistic
- [ ] Results are educational
- [ ] MITRE techniques are mapped
- [ ] Timestamps are accurate

### Interactive Features
- [ ] Stop operation works
- [ ] Delete operation works
- [ ] Confirmation dialogs appear
- [ ] Page refreshes after actions
- [ ] Status updates correctly

## 🎓 Educational Features Testing

### Learning Scenarios
- [ ] All three scenarios work
- [ ] Form population is correct
- [ ] Educational content is relevant
- [ ] Learning objectives are clear
- [ ] Difficulty progression makes sense

### MITRE ATT&CK Integration
- [ ] Techniques are accurately mapped
- [ ] Tactic badges display correctly
- [ ] Framework relationships are clear
- [ ] Educational value is high
- [ ] Industry standards are followed

### Resource Links
- [ ] MITRE ATT&CK link works
- [ ] Threat intelligence buttons respond
- [ ] Incident response buttons work
- [ ] External links open correctly
- [ ] Educational content is accessible

## 🚨 Error Handling Testing

### Graceful Degradation
- [ ] Invalid operations handled
- [ ] Database errors don't crash app
- [ ] Network issues are handled
- [ ] User errors show helpful messages
- [ ] System errors are logged

### User Feedback
- [ ] Success messages display
- [ ] Error messages are clear
- [ ] Loading states are shown
- [ ] Progress indicators work
- [ ] Confirmation dialogs appear

## 📈 Performance Testing

### Load Times
- [ ] Pages load within 3 seconds
- [ ] Images load quickly
- [ ] JavaScript executes smoothly
- [ ] Database queries are fast
- [ ] Background tasks don't block UI

### Resource Usage
- [ ] Memory usage is reasonable
- [ ] CPU usage is low
- [ ] Database size is manageable
- [ ] Network traffic is minimal
- [ ] Disk I/O is efficient

## 🔒 Security Testing

### Access Control
- [ ] Unauthenticated access is blocked
- [ ] Session management works
- [ ] Password hashing is used
- [ ] CSRF protection is active
- [ ] Input validation works

### Data Protection
- [ ] Sensitive data is not exposed
- [ ] Database is properly secured
- [ ] Logs don't contain secrets
- [ ] Error messages are safe
- [ ] User data is protected

## ✅ Final Verification

### Complete Workflow
- [ ] Login → Dashboard → Operations → Create Operation → Execute → View Results
- [ ] All steps work without errors
- [ ] Educational value is delivered
- [ ] User experience is smooth
- [ ] Learning objectives are met

### Documentation
- [ ] README.md is helpful
- [ ] operation.md is comprehensive
- [ ] QUICK_START.md is clear
- [ ] Code comments are present
- [ ] Setup instructions work

## 🎉 Success Criteria

### Functional Requirements
- [ ] All core features work
- [ ] Educational scenarios execute
- [ ] UI/UX is polished
- [ ] Performance is acceptable
- [ ] Security is adequate

### Educational Requirements
- [ ] Learning objectives are clear
- [ ] Content is accurate
- [ ] Progression is logical
- [ ] Engagement is high
- [ ] Value is demonstrated

### Technical Requirements
- [ ] Code is maintainable
- [ ] Architecture is sound
- [ ] Documentation is complete
- [ ] Testing is thorough
- [ ] Deployment is simple

---

**Testing Complete!** ✅

If all items are checked, your MarbleCone Threat Emulator is ready for educational use!

**Next Steps:**
1. Share with students or colleagues
2. Begin educational exercises
3. Collect feedback for improvements
4. Plan advanced scenarios
5. Integrate with curriculum

**For Issues:** Review logs, check documentation, or contact support. 