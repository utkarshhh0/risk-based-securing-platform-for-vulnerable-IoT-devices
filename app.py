"""
Main Streamlit application for IoT Security Platform
"""
import streamlit as st  # type: ignore
import pandas as pd  # type: ignore
import plotly.express as px  # type: ignore
import plotly.graph_objects as go  # type: ignore
from datetime import datetime
from typing import Dict, List
import time

from scanner import scan_subnet, simulate_scan
from vulnerability import analyze_device
from remediation import fix_all_vulnerabilities, fix_default_credentials, fix_risky_port, get_remediation_logs
from device_manager import load_devices, setup_new_device, add_fake_device, remove_device, merge_managed_devices
from policy import load_policy, save_policy, validate_policy
from utils import export_to_csv
import iot_simulator
from session_manager import save_session_state, load_session_state


# Page configuration
st.set_page_config(
    page_title="IoT Security Platform",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject custom CSS for a cyber-security purple theme
st.markdown("""
<style>
    /* Main background color */
    .stApp {
        background-color: #1A1A2E;
    }
    /* Sidebar background color */
    .css-1d391kg {
        background-color: #0F0F1A;
    }
    /* Text color */
    .st-emotion-cache-183lzff {
        color: #E0E0E0;
    }
    h1, h2, h3, h4, h5, h6 {
        color: #FFFFFF;
    }
    .st-emotion-cache-1629p8f span {
        color: #E0E0E0;
    }
    /* Button styling */
    .stButton>button {
        background-color: #6A0DAD;
        color: white;
        border-radius: 8px;
        border: 1px solid #8A2BE2;
    }
    .stButton>button:hover {
        background-color: #8A2BE2;
        color: white;
        border: 1px solid #6A0DAD;
    }
</style>
""", unsafe_allow_html=True)


# Initialize session state
if 'devices' not in st.session_state:
    st.session_state.devices = []
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = []
if 'policy' not in st.session_state:
    st.session_state.policy = load_policy()
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'selected_device' not in st.session_state:
    st.session_state.selected_device = None
if 'session_loaded' not in st.session_state:
    st.session_state.session_loaded = False


def add_alert(message: str, alert_type: str = "info"):
    """Add an alert to the session state."""
    st.session_state.alerts.append({
        'message': message,
        'type': alert_type,
        'timestamp': datetime.now().isoformat()
    })


def display_alerts():
    """Display alerts in the UI."""
    if st.session_state.alerts:
        for alert in st.session_state.alerts[-5:]:  # Show last 5 alerts
            if alert['type'] == 'error':
                st.markdown(f"<p style='color: #DC3545;'>{alert['message']}</p>", unsafe_allow_html=True)
            elif alert['type'] == 'success':
                st.markdown(f"<p style='color: #00FF00;'>{alert['message']}</p>", unsafe_allow_html=True)
            elif alert['type'] == 'warning':
                st.markdown(f"<p style='color: #FFA500;'>{alert['message']}</p>", unsafe_allow_html=True)
            else:
                st.markdown(f"<p style='color: #00BFFF;'>{alert['message']}</p>", unsafe_allow_html=True)


def refresh_device_data():
    """Update existing devices with latest state from simulator/managed devices and re-analyze."""
    from iot_simulator import get_device_by_ip, convert_to_scan_format, get_all_devices
    from device_manager import load_devices, get_device_by_ip as get_managed_device
    import importlib
    
    # Force reload of simulator module to get fresh data from file
    import iot_simulator
    importlib.reload(iot_simulator)
    get_device_by_ip = iot_simulator.get_device_by_ip
    convert_to_scan_format = iot_simulator.convert_to_scan_format
    
    # Get current device IPs to preserve the list
    current_device_ips = set()
    if st.session_state.devices:
        current_device_ips = {result['device']['ip'] for result in st.session_state.devices}
    
    # Update each existing device from simulator or managed devices
    updated_devices = []
    for result in st.session_state.devices:
        device_ip = result['device']['ip']
        
        # Try simulator first (will reload from file)
        simulator_device = get_device_by_ip(device_ip)
        if simulator_device:
            # Convert to scanner format with updated state
            updated_device = convert_to_scan_format(simulator_device)
            updated_devices.append(updated_device)
        else:
            # Try managed devices
            managed_device = get_managed_device(device_ip)
            if managed_device:
                # Convert managed device to scanner format
                updated_device = convert_to_scan_format(managed_device)
                updated_devices.append(updated_device)
            else:
                # Device not found, keep original (shouldn't happen but safety)
                updated_devices.append(result['device'])
    
    # Also check for any new managed devices
    managed_devices = load_devices()
    for managed in managed_devices:
        if managed.get('ip') not in current_device_ips:
            # New managed device, convert to scanner format
            updated_devices.append(convert_to_scan_format(managed))
    
    # Re-analyze all devices with updated states (this will recalculate vulnerabilities)
    analyzed_devices = []
    for device in updated_devices:
        analysis = analyze_device(device, st.session_state.policy)
        analyzed_devices.append(analysis)
    
    st.session_state.devices = analyzed_devices
    st.session_state.scan_results = analyzed_devices
    # Save session state for persistence across browser refresh
    save_session_state(analyzed_devices, st.session_state.policy)


def main():
    """Main application."""
    # Load saved session state on first load (browser refresh)
    if not st.session_state.session_loaded:
        saved_state = load_session_state()
        if saved_state:
            st.session_state.devices = saved_state.get('devices', [])
            st.session_state.scan_results = saved_state.get('devices', [])
            # Policy might have changed, so reload it
            # st.session_state.policy = saved_state.get('policy', load_policy())
        st.session_state.session_loaded = True
    
    st.title("Risk-Based Securing Platform for Vulnerable IoT Devices")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("Settings")
        
        # Show which dataset is being used
        from pathlib import Path
        dataset_file = Path("data/iot_vulnerable_devices.json")
        device_count = len(iot_simulator.get_all_devices())
        if dataset_file.exists():
            st.caption(f"📁 Dataset: **iot_vulnerable_devices.json** ({device_count} devices)")
        else:
            st.caption(f"📁 Dataset: **Default** ({device_count} devices)")
        
        # Theme toggle (placeholder - Streamlit handles this)
        st.markdown("### Scan Configuration")
        
        # Mode selection
        scan_mode = st.radio(
            "Scan Mode",
            ["Realistic Simulation Mode", "Real Device Scan Mode"],
            index=0,
            help="Realistic Simulation uses deterministic IoT device dataset. Real Device Scan scans actual network."
        )
        
        use_simulation = (scan_mode == "Realistic Simulation Mode")
        use_realistic = use_simulation  # Use deterministic simulator
        
        scan_subnet_input = st.text_input(
            "Subnet to Scan",
            value="192.168.1.0/24",
            help="Enter CIDR notation (e.g., 192.168.1.0/24) or single IP"
        )
        
        if st.button("Scan Network", type="primary", use_container_width=True):
            with st.spinner("Scanning network..."):
                if use_simulation:
                    discovered = simulate_scan(scan_subnet_input, use_realistic=use_realistic)
                    add_alert(f"Realistic simulation scan completed: Found {len(discovered)} devices", "success")
                else:
                    discovered = scan_subnet(scan_subnet_input)
                    add_alert(f"Real device scan completed: Found {len(discovered)} devices", "success")
                
                # Merge with managed devices
                discovered = merge_managed_devices(discovered)
                
                # Analyze devices
                analyzed_devices = []
                for device in discovered:
                    analysis = analyze_device(device, st.session_state.policy)
                    analyzed_devices.append(analysis)
                
                st.session_state.scan_results = analyzed_devices
                st.session_state.devices = analyzed_devices
                # Save session state for persistence across browser refresh
                save_session_state(analyzed_devices, st.session_state.policy)
                st.rerun()
        
        st.markdown("---")
        st.markdown("### Device Management")
        if st.button("Setup New Device", use_container_width=True):
            st.session_state.show_setup_device = True
        
        if st.button("Restore Original Dataset", use_container_width=True, help="Restore all devices with original vulnerabilities"):
            from session_manager import restore_default_dataset
            from iot_simulator import DEFAULT_DEVICES, save_simulated_devices
            with st.spinner("Restoring original dataset..."):
                try:
                    save_simulated_devices(DEFAULT_DEVICES)
                    # Clear session state to force reload
                    from session_manager import clear_session_state
                    clear_session_state()
                    # Refresh device data
                    refresh_device_data()
                    add_alert("Original dataset restored with all vulnerabilities!", "success")
                    st.rerun()
                except Exception as e:
                    add_alert(f"Failed to restore dataset: {str(e)}", "error")
        
        st.markdown("---")
        st.markdown("### Security Policy")
        if st.button("Edit Policy", use_container_width=True):
            st.session_state.show_policy = True
    
    # Main content area
    display_alerts()
    
    # Tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["Dashboard", "Device Details", "Remediation Logs", "Export"])
    
    with tab1:
        display_dashboard()
    
    with tab2:
        display_device_details()
    
    with tab3:
        display_remediation_logs()
    
    with tab4:
        display_export()
    
    # Modals/Dialogs
    if st.session_state.get('show_setup_device', False):
        display_setup_device_dialog()
    
    if st.session_state.get('show_policy', False):
        display_policy_dialog()


def display_dashboard():
    """Display main dashboard with device overview."""
    st.header("Security Dashboard")
    
    if not st.session_state.devices:
        st.markdown("<p style='color: #00BFFF;'>Start by scanning your network using the sidebar controls.</p>", unsafe_allow_html=True)
        return
    
    # Calculate statistics
    total_devices = len(st.session_state.devices)
    critical_devices = sum(1 for d in st.session_state.devices if d['risk_category'] == 'Critical')
    high_risk_devices = sum(1 for d in st.session_state.devices if d['risk_category'] == 'High')
    medium_risk_devices = sum(1 for d in st.session_state.devices if d['risk_category'] == 'Medium')
    low_risk_devices = sum(1 for d in st.session_state.devices if d['risk_category'] == 'Low')
    total_vulnerabilities = sum(len(d['vulnerabilities']) for d in st.session_state.devices)
    avg_risk_score = sum(d['risk_score'] for d in st.session_state.devices) / total_devices if total_devices > 0 else 0
    
    # Enhanced metrics with better styling
    st.markdown("### Security Overview")
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            "Total Devices", 
            total_devices,
            help="Number of IoT devices discovered on the network"
        )
    
    with col2:
        st.metric(
            "Critical Risk", 
            critical_devices,
            delta=f"{critical_devices/total_devices*100:.1f}%" if total_devices > 0 else "0%",
            delta_color="inverse",
            help="Devices requiring immediate attention"
        )
    
    with col3:
        st.metric(
            "High Risk", 
            high_risk_devices,
            delta=f"{high_risk_devices/total_devices*100:.1f}%" if total_devices > 0 else "0%",
            delta_color="inverse",
            help="Devices with significant security concerns"
        )
    
    with col4:
        st.metric(
            "Total Vulnerabilities", 
            total_vulnerabilities,
            help="Total number of security vulnerabilities detected"
        )
    
    with col5:
        st.metric(
            "Avg Risk Score", 
            f"{avg_risk_score:.1f}",
            help="Average risk score across all devices (0-100)"
        )
    
    # Risk score progress bar
    st.markdown("### Overall Security Posture")
    overall_risk = (critical_devices * 100 + high_risk_devices * 60 + medium_risk_devices * 30) / total_devices if total_devices > 0 else 0
    security_score = max(0, 100 - overall_risk)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.progress(security_score / 100, text=f"Security Score: {security_score:.1f}/100")
    with col2:
        if security_score >= 80:
            st.markdown("<h4 style='color: #00FF00;'>Excellent</h4>")
        elif security_score >= 60:
            st.markdown("<h4 style='color: #00BFFF;'>Good</h4>")
        elif security_score >= 40:
            st.markdown("<h4 style='color: #FFA500;'>Fair</h4>")
        else:
            st.markdown("<h4 style='color: #DC3545;'>Poor</h4>")
    
    st.markdown("---")
    
    # Charts section
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Risk Distribution")
        # Pie chart for risk categories
        risk_counts = {
            'Critical': critical_devices,
            'High': high_risk_devices,
            'Medium': medium_risk_devices,
            'Low': low_risk_devices
        }
        
        if sum(risk_counts.values()) > 0:
            fig_pie = px.pie(
                values=list(risk_counts.values()),
                names=list(risk_counts.keys()),
                color_discrete_map={
                    'Critical': '#FF00FF',
                    'High': '#DC3545',
                    'Medium': '#FFA500',
                    'Low': '#00BFFF'
                },
                hole=0.4
            )
            fig_pie.update_layout(
                showlegend=True, 
                height=350, 
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='#E0E0E0'
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.markdown("<p style='color: #00BFFF;'>No devices to display</p>", unsafe_allow_html=True)
    
    with col2:
        st.markdown("### Vulnerability Types")
        # Count vulnerability types
        vuln_types = {}
        for result in st.session_state.devices:
            for vuln in result['vulnerabilities']:
                vuln_type = vuln.get('type', 'Unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        if vuln_types:
            fig_bar = px.bar(
                x=list(vuln_types.keys()),
                y=list(vuln_types.values()),
                labels={'x': 'Vulnerability Type', 'y': 'Count'},
                color=list(vuln_types.values()),
                color_continuous_scale='Purples'
            )
            fig_bar.update_layout(
                showlegend=False, 
                height=350, 
                xaxis_tickangle=-45,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='#E0E0E0'
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.markdown("<p style='color: #00BFFF;'>No vulnerabilities detected</p>", unsafe_allow_html=True)
    
    # Risk score distribution
    st.markdown("### Risk Score Distribution")
    risk_scores = [d['risk_score'] for d in st.session_state.devices]
    if risk_scores:
        fig_hist = px.histogram(
            x=risk_scores,
            nbins=20,
            labels={'x': 'Risk Score', 'y': 'Number of Devices'},
            color_discrete_sequence=['#FF00FF']
        )
        fig_hist.update_layout(
            height=300, 
            showlegend=False,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#E0E0E0'
        )
        st.plotly_chart(fig_hist, use_container_width=True)
    
    st.markdown("---")
    
    # Top vulnerable devices
    st.markdown("### Top Vulnerable Devices")
    sorted_devices = sorted(st.session_state.devices, key=lambda x: x['risk_score'], reverse=True)
    top_devices = sorted_devices[:5]
    
    for i, result in enumerate(top_devices, 1):
        device = result['device']
        risk_score = result['risk_score']
        risk_category = result['risk_category']
        vuln_count = len(result['vulnerabilities'])
        
        # Color based on risk
        if risk_category == 'Critical':
            color = '#FF4444'
        elif risk_category == 'High':
            color = '#FF8800'
        elif risk_category == 'Medium':
            color = '#FFBB00'
        else:
            color = '#88FF88'
        
        with st.container():
            col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
            with col1:
                st.markdown(f"**{device.get('hostname', 'Unknown')}**")
                st.caption(f"IP: {device.get('ip')}")
            with col2:
                st.markdown(f"**{vuln_count}** vulnerabilities")
                st.caption(f"Ports: {', '.join(map(str, device.get('open_ports', [])))}")
            with col3:
                st.markdown(f"**Risk Score**")
                st.markdown(f"### {risk_score:.0f}")
            with col4:
                st.markdown(f"**Category**")
                st.markdown(f"### {risk_category}")
            
            # Progress bar for risk score
            st.progress(risk_score / 100, text=f"Risk Level: {risk_score:.1f}/100")
            st.markdown("---")
    
    # Device table with enhanced styling
    st.markdown("### Complete Device Inventory")
    
    device_data = []
    for result in st.session_state.devices:
        device = result['device']
        device_data.append({
            'IP Address': device.get('ip'),
            'Hostname': device.get('hostname', 'Unknown'),
            'Open Ports': ', '.join(map(str, device.get('open_ports', []))),
            'Risk Score': result['risk_score'],
            'Risk Category': result['risk_category'],
            'Vulnerabilities': len(result['vulnerabilities'])
        })
    
    df = pd.DataFrame(device_data)
    
    # Color code by risk category
    def color_risk(val):
        if val == 'Critical':
            return 'color: #FF00FF; font-weight: bold'
        elif val == 'High':
            return 'color: #DC3545; font-weight: bold'
        elif val == 'Medium':
            return 'color: #FFA500;'
        else:
            return 'color: #00BFFF;'
    
    def color_score(val):
        if val >= 70:
            return 'color: #FF00FF; font-weight: bold'
        elif val >= 40:
            return 'color: #DC3545;'
        elif val >= 20:
            return 'color: #FFA500;'
        else:
            return 'color: #00BFFF;'
    
    styled_df = df.style.applymap(color_risk, subset=['Risk Category']).applymap(color_score, subset=['Risk Score'])
    st.dataframe(styled_df, use_container_width=True, hide_index=True, height=400)
    
    # Quick actions
    st.markdown("---")
    st.markdown("### Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔧 Fix All Critical Devices", type="primary", use_container_width=True):
            critical = [d for d in st.session_state.devices if d['risk_category'] == 'Critical']
            if critical:
                with st.spinner(f"Applying fixes to {len(critical)} critical devices..."):
                    fixes_summary = []
                    total_risk_reduction = 0
                    
                    for result in critical:
                        device_ip = result['device']['ip']
                        old_risk = result['risk_score']
                        hostname = result['device'].get('hostname', 'Unknown')
                        
                        # Check if device has vulnerabilities to fix
                        if not result.get('vulnerabilities'):
                            fixes_summary.append({
                                'ip': device_ip,
                                'hostname': hostname,
                                'old_risk': old_risk,
                                'new_risk': old_risk,
                                'reduction': 0,
                                'status': 'skipped',
                                'message': 'No vulnerabilities to fix'
                            })
                            continue
                        
                        fix_result = fix_all_vulnerabilities(
                            device_ip,
                            result['vulnerabilities'],
                            st.session_state.policy
                        )
                        
                        if fix_result['success']:
                            new_risk = fix_result.get('new_risk', old_risk)
                            risk_reduction = old_risk - new_risk
                            total_risk_reduction += risk_reduction
                            fixes_applied = fix_result.get('fixes_applied', [])
                            fixes_summary.append({
                                'ip': device_ip,
                                'hostname': hostname,
                                'old_risk': old_risk,
                                'new_risk': new_risk,
                                'reduction': risk_reduction,
                                'status': 'success',
                                'fixes': fixes_applied
                            })
                        else:
                            # Fix failed - log the error
                            fixes_summary.append({
                                'ip': device_ip,
                                'hostname': hostname,
                                'old_risk': old_risk,
                                'new_risk': old_risk,
                                'reduction': 0,
                                'status': 'failed',
                                'message': fix_result.get('message', 'Unknown error')
                            })
                    
                    # Refresh device data from simulator to get updated states
                    # Force reload from file to get latest fixes
                    refresh_device_data()
                    # Save session state after fixes
                    save_session_state(st.session_state.devices, st.session_state.policy)
                    
                    # Verify fixes were applied by checking if devices are still critical
                    still_critical = [d for d in st.session_state.devices if d['risk_category'] == 'Critical']
                    if still_critical and len(still_critical) < len(critical):
                        st.markdown(f"<p style='color: #00BFFF;'>{len(critical) - len(still_critical)} devices are no longer critical after fixes!</p>", unsafe_allow_html=True)
                    
                    # Show summary with before/after comparison
                    if fixes_summary:
                        st.markdown(f"<p style='color: #00FF00;'>Successfully fixed {len(fixes_summary)} critical devices!</p>", unsafe_allow_html=True)
                        st.markdown(f"<p style='color: #00BFFF;'>**Total Risk Reduction:** {total_risk_reduction:.1f} points across all devices</p>", unsafe_allow_html=True)
                        
                        with st.expander("Detailed Fix Summary - Devices Still Visible with Reduced Risk"):
                            for summary in fixes_summary:
                                # Check if device is still critical after fix
                                current_device = next((d for d in st.session_state.devices if d['device']['ip'] == summary['ip']), None)
                                
                                if summary.get('status') == 'failed':
                                    st.markdown(f"<p style='color: #DC3545;'>**{summary['ip']}** ({summary.get('hostname', 'Unknown')}) - {summary.get('message', 'Fix failed')}</p>", unsafe_allow_html=True)
                                elif summary.get('status') == 'skipped':
                                    st.markdown(f"<p style='color: #FFA500;'>**{summary['ip']}** ({summary.get('hostname', 'Unknown')}) - {summary.get('message', 'Skipped')}</p>", unsafe_allow_html=True)
                                elif current_device:
                                    new_category = current_device['risk_category']
                                    st.write(f"**{summary['ip']}** ({summary.get('hostname', 'Unknown')})")
                                    st.write(f"   Risk: {summary['old_risk']:.1f} → **{summary['new_risk']:.1f}** ({new_category})")
                                    if summary.get('reduction', 0) > 0:
                                        st.write(f"   Reduction: **-{summary['reduction']:.1f} points**")
                                    if summary.get('fixes'):
                                        st.write(f"   Fixes: {', '.join(summary['fixes'])}")
                                    st.write("Device still visible in list with updated risk score")
                                else:
                                    st.markdown(f"<p style='color: #FFA500;'>**{summary['ip']}** - Device not found after refresh</p>", unsafe_allow_html=True)
                                st.markdown("---")
                        
                        add_alert(f"Fixed {len(fixes_summary)} critical devices. Devices remain visible with reduced risk scores. Total reduction: {total_risk_reduction:.1f} points", "success")
                    else:
                        add_alert("No fixes were applied", "warning")
                    
                    st.rerun()
            else:
                add_alert("No critical devices found", "info")
    
    with col2:
        if st.button("Refresh Analysis", use_container_width=True):
            with st.spinner("Refreshing device analysis from files..."):
                # Refresh from simulator and re-analyze (reloads from files)
                refresh_device_data()
                # Save updated state
                save_session_state(st.session_state.devices, st.session_state.policy)
                add_alert(f"Refreshed analysis for {len(st.session_state.devices)} devices from files", "success")
                st.rerun()
    
    with col3:
        if st.button("Export Report", use_container_width=True):
            device_data = []
            for result in st.session_state.devices:
                device = result['device']
                device_data.append({
                    'ip': device.get('ip'),
                    'hostname': device.get('hostname', 'Unknown'),
                    'open_ports': ', '.join(map(str, device.get('open_ports', []))),
                    'risk_score': result['risk_score'],
                    'risk_category': result['risk_category'],
                    'vulnerability_count': len(result['vulnerabilities']),
                    'vulnerabilities': '; '.join([v.get('type', '') for v in result['vulnerabilities']])
                })
            
            filepath = export_to_csv(device_data, "device_inventory")
            if filepath:
                add_alert(f"Report exported to {filepath}", "success")
                st.rerun()


def display_device_details():
    """Display detailed view for individual devices."""
    st.header("Device Details")
    
    if not st.session_state.devices:
        st.markdown("<p style='color: #00BFFF;'>No devices scanned yet. Start a scan from the sidebar.</p>", unsafe_allow_html=True)
        return
    
    # Device selector
    device_options = {
        f"{r['device']['ip']} - {r['device'].get('hostname', 'Unknown')} ({r['risk_category']})": i
        for i, r in enumerate(st.session_state.devices)
    }
    
    selected = st.selectbox("Select Device", list(device_options.keys()))
    device_idx = device_options[selected]
    result = st.session_state.devices[device_idx]
    device = result['device']
    
    # Device information
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Device Information")
        st.write(f"**IP Address:** {device.get('ip')}")
        st.write(f"**Hostname:** {device.get('hostname', 'Unknown')}")
        st.write(f"**Open Ports:** {', '.join(map(str, device.get('open_ports', [])))}")
        if device.get('device_info'):
            st.write(f"**Server Info:** {device.get('device_info', {}).get('server', 'Unknown')}")
    
    with col2:
        st.subheader("Risk Assessment")
        st.metric("Risk Score", f"{result['risk_score']}/100")
        st.write(f"**Risk Category:** {result['risk_category']}")
        st.write(f"**Vulnerabilities Found:** {len(result['vulnerabilities'])}")
        
        # Show risk details if available
        if result.get('risk_details'):
            risk_details = result['risk_details']
            st.write(f"**Device Type:** {risk_details.get('device_type', 'unknown').title()}")
            st.write(f"**Multiplier:** {risk_details.get('multiplier', 1.0)}x")
            if risk_details.get('years_old_firmware', 0) > 0:
                st.write(f"**Firmware Age:** {risk_details.get('years_old_firmware')} years old")
    
    # Risk Explanation
    if result.get('explanation'):
        st.markdown("---")
        st.markdown("### Risk Explanation")
        st.markdown(result['explanation'])
    
    # Vulnerabilities
    st.markdown("---")
    st.subheader("Vulnerabilities & Fixes")
    
    if not result['vulnerabilities']:
        st.markdown("<p style='color: #00FF00;'>No vulnerabilities detected!</p>", unsafe_allow_html=True)
    else:
        for i, vuln in enumerate(result['vulnerabilities']):
            with st.expander(f"{vuln.get('type', 'Unknown')} - {vuln.get('severity', 'medium').upper()}"):
                st.write(f"**Description:** {vuln.get('description', 'No description')}")
                
                if vuln['type'] == 'default_credentials':
                    st.write(f"**Username:** {vuln.get('username')}")
                    st.write(f"**Password:** {vuln.get('password')}")
                    st.write(f"**Risk Contribution:** +{vuln.get('risk_contribution', 0)} points")
                    if st.button(f"Fix Credentials", key=f"fix_cred_{i}"):
                        with st.spinner("Fixing credentials..."):
                            fix_result = fix_default_credentials(
                                device['ip'],
                                vuln.get('username'),
                                st.session_state.policy
                            )
                            if fix_result['success']:
                                old_risk = fix_result.get('fix_record', {}).get('old_risk', result['risk_score'])
                                new_risk = fix_result.get('risk_result', {}).get('risk_score', result['risk_score'])
                                risk_reduction = old_risk - new_risk
                                
                                st.markdown(f"<p style='color: #00FF00;'>{fix_result['message']}</p>", unsafe_allow_html=True)
                                st.code(f"New Password: {fix_result['new_password']}", language=None)
                                st.metric("Risk Reduction", f"{risk_reduction:.1f} points", 
                                         delta=f"{old_risk:.1f} → {new_risk:.1f}")
                                add_alert(f"Credentials fixed for {device['ip']} - Risk reduced by {risk_reduction:.1f}", "success")
                                # Refresh device data and re-analyze
                                refresh_device_data()
                                save_session_state(st.session_state.devices, st.session_state.policy)
                                st.rerun()
                
                elif vuln['type'] == 'risky_port':
                    st.write(f"**Port:** {vuln.get('port')}")
                    st.write(f"**Service:** {vuln.get('service', vuln.get('name', 'Unknown'))}")
                    st.write(f"**Risk Contribution:** +{vuln.get('risk_contribution', 0)} points")
                    if st.button(f"Close Port", key=f"fix_port_{i}"):
                        with st.spinner("Closing port..."):
                            fix_result = fix_risky_port(device['ip'], vuln.get('port'), st.session_state.policy)
                            if fix_result['success']:
                                old_risk = fix_result.get('fix_record', {}).get('old_risk', result['risk_score'])
                                new_risk = fix_result.get('risk_result', {}).get('risk_score', result['risk_score'])
                                risk_reduction = old_risk - new_risk
                                
                                st.markdown(f"<p style='color: #00FF00;'>{fix_result['message']}</p>", unsafe_allow_html=True)
                                st.metric("Risk Reduction", f"{risk_reduction:.1f} points",
                                         delta=f"{old_risk:.1f} → {new_risk:.1f}")
                                add_alert(f"Port {vuln.get('port')} closed for {device['ip']} - Risk reduced by {risk_reduction:.1f}", "success")
                                # Refresh device data and re-analyze
                                refresh_device_data()
                                save_session_state(st.session_state.devices, st.session_state.policy)
                                st.rerun()
                
                elif vuln['type'] in ['eol_firmware', 'outdated_firmware']:
                    st.write(f"**Risk Contribution:** +{vuln.get('risk_contribution', 0)} points")
                    if vuln.get('years_old'):
                        st.write(f"**Firmware Age:** {vuln.get('years_old')} years old")
                    if vuln.get('last_update_year'):
                        st.write(f"**Last Update:** {vuln.get('last_update_year')}")
                    
                    if st.button(f"🔧 Update Firmware (Simulated)", key=f"fix_firmware_{i}"):
                        with st.spinner("Updating firmware..."):
                            from remediation import fix_firmware
                            fix_result = fix_firmware(device['ip'], st.session_state.policy)
                            if fix_result['success']:
                                old_risk = fix_result.get('fix_record', {}).get('old_risk', result['risk_score'])
                                new_risk = fix_result.get('risk_result', {}).get('risk_score', result['risk_score'])
                                risk_reduction = old_risk - new_risk
                                
                                st.markdown(f"<p style='color: #00FF00;'>{fix_result['message']}</p>", unsafe_allow_html=True)
                                st.metric("Risk Reduction", f"{risk_reduction:.1f} points",
                                         delta=f"{old_risk:.1f} → {new_risk:.1f}")
                                add_alert(f"Firmware updated for {device['ip']} - Risk reduced by {risk_reduction:.1f}", "success")
                                # Refresh device data and re-analyze
                                refresh_device_data()
                                save_session_state(st.session_state.devices, st.session_state.policy)
                                st.rerun()
                            else:
                                st.markdown("<p style='color: #FFA500;'>Firmware update requires vendor support. Contact device manufacturer.</p>", unsafe_allow_html=True)
                                if vuln.get('eol_date'):
                                    st.write(f"**EOL Date:** {vuln.get('eol_date')}")
                                if vuln.get('vendor'):
                                    st.write(f"**Vendor:** {vuln.get('vendor')}")
        
        # Fix all button
        st.markdown("---")
        if st.button("Fix All Vulnerabilities", type="primary", use_container_width=True):
            with st.spinner("Applying all fixes..."):
                old_risk = result['risk_score']
                fix_result = fix_all_vulnerabilities(
                    device['ip'],
                    result['vulnerabilities'],
                    st.session_state.policy
                )
                if fix_result['success']:
                    new_risk = fix_result.get('new_risk', old_risk)
                    risk_reduction = old_risk - new_risk
                    
                    st.markdown(f"<p style='color: #00FF00;'>{fix_result['message']}</p>", unsafe_allow_html=True)
                    
                    # Show risk reduction
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Risk Before", f"{old_risk:.1f}/100")
                    with col2:
                        st.metric("Risk After", f"{new_risk:.1f}/100", 
                                 delta=f"-{risk_reduction:.1f} points", delta_color="inverse")
                    
                    if fix_result.get('credentials'):
                        st.subheader("Generated Credentials")
                        for username, password in fix_result['credentials'].items():
                            st.code(f"{username}: {password}", language=None)
                    
                    st.info(f"**Fixes Applied:** {', '.join(fix_result.get('fixes_applied', []))}")
                    add_alert(f"All fixes applied to {device['ip']} - Risk reduced from {old_risk:.1f} to {new_risk:.1f}", "success")
                    # Refresh device data and re-analyze
                    refresh_device_data()
                    save_session_state(st.session_state.devices, st.session_state.policy)
                    st.rerun()


def display_remediation_logs():
    """Display remediation action logs."""
    st.header("Remediation Logs")
    
    logs = get_remediation_logs()
    
    if not logs:
        st.markdown("<p style='color: #00BFFF;'>No remediation actions logged yet.</p>", unsafe_allow_html=True)
        return
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        filter_device = st.selectbox(
            "Filter by Device",
            ["All"] + list(set(log['device_ip'] for log in logs))
        )
    with col2:
        filter_action = st.selectbox(
            "Filter by Action",
            ["All"] + list(set(log['action'] for log in logs))
        )
    
    # Filter logs
    filtered_logs = logs
    if filter_device != "All":
        filtered_logs = [log for log in filtered_logs if log['device_ip'] == filter_device]
    if filter_action != "All":
        filtered_logs = [log for log in filtered_logs if log['action'] == filter_action]
    
    # Display logs
    for log in reversed(filtered_logs[-50:]):  # Show last 50
        with st.expander(f"{log['timestamp']} - {log['action']} on {log['device_ip']}"):
            st.write(f"**Status:** {log['status']}")
            if log.get('details'):
                st.json(log['details'])


def display_export():
    """Display export options."""
    st.header("Export Data")
    
    if not st.session_state.devices:
        st.info("No data to export. Scan devices first.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Export Device Inventory")
        if st.button("Export Devices CSV", use_container_width=True):
            device_data = []
            for result in st.session_state.devices:
                device = result['device']
                device_data.append({
                    'ip': device.get('ip'),
                    'hostname': device.get('hostname', 'Unknown'),
                    'open_ports': ', '.join(map(str, device.get('open_ports', []))),
                    'risk_score': result['risk_score'],
                    'risk_category': result['risk_category'],
                    'vulnerability_count': len(result['vulnerabilities']),
                    'vulnerabilities': '; '.join([v.get('type', '') for v in result['vulnerabilities']])
                })
            
            filepath = export_to_csv(device_data, "device_inventory")
            if filepath:
                st.markdown(f"<p style='color: #00FF00;'>Exported to {filepath}</p>", unsafe_allow_html=True)
                add_alert(f"Device inventory exported to {filepath}", "success")
    
    with col2:
        st.subheader("Export Remediation Logs")
        if st.button("Export Logs CSV", use_container_width=True):
            logs = get_remediation_logs()
            if logs:
                filepath = export_to_csv(logs, "remediation_logs")
                if filepath:
                    st.markdown(f"<p style='color: #00FF00;'>Exported to {filepath}</p>", unsafe_allow_html=True)
                    add_alert(f"Remediation logs exported to {filepath}", "success")
            else:
                st.markdown("<p style='color: #FFA500;'>No logs to export</p>", unsafe_allow_html=True)


def display_setup_device_dialog():
    """Display dialog for setting up new IoT devices with full configuration."""
    from datetime import datetime
    from device_manager import setup_new_device
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("Setup New IoT Device")
    
    with st.sidebar.form("setup_device_form"):
        st.markdown("### Basic Information")
        ip = st.text_input("IP Address *", value="192.168.1.200", help="Device IP address")
        hostname = st.text_input("Hostname *", value="New-IoT-Device", help="Device hostname")
        
        device_types = ['camera', 'router', 'plug', 'sensor', 'bulb', 'thermostat', 'doorbell', 'other']
        device_type = st.selectbox("Device Type *", device_types, index=0, help="Type of IoT device")
        
        st.markdown("### Network Configuration")
        ports_input = st.text_input("Open Ports (comma-separated) *", value="80,443", 
                                    help="Comma-separated list of open ports (e.g., 80,443,554)")
        
        st.markdown("### Device Details")
        manufacturer = st.text_input("Manufacturer", value="", help="Device manufacturer (optional)")
        model = st.text_input("Model", value="", help="Device model (optional)")
        firmware_version = st.text_input("Firmware Version", value="1.0.0", help="Current firmware version")
        
        st.markdown("### Security Settings")
        default_creds = st.checkbox("Has Default Credentials", value=False, 
                                    help="Device uses default/weak credentials")
        last_update_year = st.number_input("Last Firmware Update Year", 
                                          min_value=2010, max_value=datetime.now().year, 
                                          value=datetime.now().year - 2,
                                          help="Year of last firmware update")
        
        submitted = st.form_submit_button("Setup Device", type="primary", use_container_width=True)
        
        if submitted:
            if not ip or not hostname:
                add_alert("IP Address and Hostname are required", "error")
            else:
                try:
                    ports = [int(p.strip()) for p in ports_input.split(',') if p.strip()]
                    if not ports:
                        add_alert("At least one port is required", "error")
                    else:
                        device_data = {
                            'ip': ip.strip(),
                            'hostname': hostname.strip(),
                            'device_type': device_type,
                            'open_ports': ports,
                            'manufacturer': manufacturer.strip() if manufacturer else 'Unknown',
                            'model': model.strip() if model else 'Unknown',
                            'firmware_version': firmware_version.strip() if firmware_version else '1.0.0',
                            'default_creds': default_creds,
                            'last_update_year': int(last_update_year),
                            'simulated_cves': []
                        }
                        
                        result = setup_new_device(device_data)
                        if result['success']:
                            add_alert(result['message'], "success")
                            # Refresh all device data to include the new device
                            refresh_device_data()
                            save_session_state(st.session_state.devices, st.session_state.policy)
                        else:
                            add_alert(result['message'], "error")
                except ValueError as e:
                    add_alert(f"Invalid input: {str(e)}", "error")
            
            st.session_state.show_setup_device = False
            st.rerun()
    
    if st.sidebar.button("Cancel", use_container_width=True):
        st.session_state.show_setup_device = False
        st.rerun()


def display_policy_dialog():
    """Display dialog for editing security policy."""
    st.sidebar.markdown("---")
    st.sidebar.subheader("Security Policy")
    
    with st.sidebar.form("policy_form"):
        st.markdown("### Password Policy")
        password_length = st.slider("Password Length", 8, 32, st.session_state.policy.get('password_length', 16))
        password_special = st.checkbox("Require Special Characters", st.session_state.policy.get('password_special_chars', True))
        
        st.markdown("### Network Policy")
        allowed_ports_input = st.text_input("Allowed Ports (comma-separated)", 
                                           value=','.join(map(str, st.session_state.policy.get('allowed_ports', [443]))))
        
        st.markdown("### Risk Thresholds")
        threshold_critical = st.slider("Critical Threshold", 50, 100, st.session_state.policy.get('risk_threshold_critical', 70))
        threshold_high = st.slider("High Threshold", 20, 80, st.session_state.policy.get('risk_threshold_high', 40))
        threshold_medium = st.slider("Medium Threshold", 10, 50, st.session_state.policy.get('risk_threshold_medium', 20))
        
        submitted = st.form_submit_button("Save Policy", use_container_width=True)
        
        if submitted:
            try:
                allowed_ports = [int(p.strip()) for p in allowed_ports_input.split(',')]
                new_policy = {
                    'password_length': password_length,
                    'password_special_chars': password_special,
                    'allowed_ports': allowed_ports,
                    'risk_threshold_critical': threshold_critical,
                    'risk_threshold_high': threshold_high,
                    'risk_threshold_medium': threshold_medium
                }
                
                is_valid, message = validate_policy(new_policy)
                if is_valid:
                    st.session_state.policy.update(new_policy)
                    save_policy(st.session_state.policy)
                    add_alert("Policy saved successfully", "success")
                    # Refresh analysis since policy affects risk scores
                    if st.session_state.devices:
                        refresh_device_data()
                        save_session_state(st.session_state.devices, st.session_state.policy)
                else:
                    add_alert(f"Policy validation failed: {message}", "error")
            except ValueError:
                add_alert("Invalid port numbers", "error")
            
            st.session_state.show_policy = False
            st.rerun()
    
    if st.sidebar.button("Cancel", key="cancel_policy", use_container_width=True):
        st.session_state.show_policy = False
        st.rerun()


if __name__ == "__main__":
    main()

