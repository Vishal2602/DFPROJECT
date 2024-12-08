import pandas as pd

# Load processed log files
apache_logs = pd.read_csv('data/processed/apache_access.csv')
firewall_logs = pd.read_csv('data/processed/firewall.csv')
system_logs = pd.read_csv('data/processed/system.csv')

# Suspicious IPs from detection
suspicious_ips = ['172.16.0.3', '192.168.1.101']

# Filter logs by suspicious IPs
suspicious_apache_logs = apache_logs[apache_logs['ip'].isin(suspicious_ips)]
suspicious_firewall_logs = firewall_logs[firewall_logs['source_ip'].isin(suspicious_ips)]
suspicious_system_logs = system_logs[system_logs['user'].isin(suspicious_ips)]

# Save suspicious logs to files
suspicious_apache_logs.to_csv('reports/suspicious_apache_logs.csv', index=False)
suspicious_firewall_logs.to_csv('reports/suspicious_firewall_logs.csv', index=False)
suspicious_system_logs.to_csv('reports/suspicious_system_logs.csv', index=False)

print("Suspicious logs saved to 'reports/' directory.")

