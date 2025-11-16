# Quick Start Guide

## Installation (5 minutes)

1. **Install Python 3.9+** (if not already installed)
   - Download from https://www.python.org/downloads/
   - Make sure to check "Add Python to PATH" during installation

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run app.py
   ```
   Or on Windows, double-click `run.bat`

4. **Access the dashboard**
   - Browser should open automatically
   - If not, navigate to: http://localhost:8501

## First Steps

### Demo Mode (Recommended for First Run)

1. **Enable Simulation Mode** (checkbox in sidebar)
2. **Enter subnet**: `192.168.1.0/24`
3. **Click "🔍 Scan Network"**
4. Wait a few seconds for simulated devices to appear
5. Explore the dashboard tabs:
   - **Dashboard**: Overview of all devices
   - **Device Details**: Click a device to see vulnerabilities
   - **Remediation Logs**: See fix history
   - **Export**: Download CSV reports

### Try These Features

1. **View Risk Scores**: Check the color-coded device table
2. **Fix a Vulnerability**: 
   - Go to "Device Details" tab
   - Select a device with vulnerabilities
   - Click "🔧 Fix All Vulnerabilities"
   - View generated passwords
3. **Add a Fake Device**:
   - Click "➕ Add Fake Device" in sidebar
   - Enter IP: `192.168.1.200`
   - Hostname: `My-Test-Device`
   - Ports: `80,443,22`
   - Click "Add Device"
4. **Customize Policy**:
   - Click "⚙️ Edit Policy" in sidebar
   - Adjust password length
   - Add allowed ports (e.g., `80,443,8080`)
   - Save policy
5. **Export Data**:
   - Go to "Export" tab
   - Click "📥 Export Devices CSV"
   - Check `exports/` folder for the file

## Troubleshooting

**Port 8501 already in use?**
```bash
streamlit run app.py --server.port 8502
```

**Import errors?**
```bash
pip install --upgrade -r requirements.txt
```

**No devices found in scan?**
- Use Simulation Mode for demos
- Check firewall settings
- Ensure you're scanning the correct subnet

## Next Steps

- Read the full README.md for detailed documentation
- Review the SRS document for requirements
- Customize security policies for your environment
- Add more fake devices for testing

Happy scanning! 🔒

