import pandas as pd
import re
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Correct paths
apache_log_path = r"data\raw\apache_access.log"
firewall_log_path = r"data\raw\firewall.log"
system_log_path = r"data\raw\system.log"
processed_dir = r"data\processed"

# Ensure processed directory exists
os.makedirs(processed_dir, exist_ok=True)

def parse_apache_logs(log_file):
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.+?)\] "(?P<request>.+?)" (?P<status>\d+) (?P<size>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"'
    )
    logs = []
    try:
        with open(log_file, 'r') as file:
            for line in file:
                match = log_pattern.match(line)
                if match:
                    logs.append(match.groupdict())
    except FileNotFoundError:
        logging.error(f"File '{log_file}' not found.")
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"Error reading Apache logs: {e}")
        return pd.DataFrame()

    df = pd.DataFrame(logs)
    if df.empty:
        logging.warning(f"No valid log entries found in '{log_file}'.")
        return df

    try:
        df['time'] = pd.to_datetime(df['time'], format='%d/%b/%Y:%H:%M:%S %z')
        df['status'] = df['status'].astype(int)
        df['size'] = df['size'].astype(int)
    except Exception as e:
        logging.error(f"Error processing Apache log data: {e}")
        return pd.DataFrame()

    logging.info(f"Parsed {len(df)} entries from '{log_file}'.")
    return df

def preprocess_firewall_logs(log_file):
    logs = []
    pattern = re.compile(r'(\w+)=([^\s]+)')

    try:
        with open(log_file, 'r') as file:
            for line in file:
                matches = pattern.findall(line)
                if matches:
                    log_entry = {key: value for key, value in matches}
                    logs.append(log_entry)
    except FileNotFoundError:
        logging.error(f"File '{log_file}' not found.")
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"Error processing firewall logs: {e}")
        return pd.DataFrame()

    if logs:
        df = pd.DataFrame(logs)
        if 'port' in df.columns:
            try:
                df['port'] = df['port'].astype(int)
            except ValueError:
                logging.warning("Non-integer values found in 'port' column. Setting to NaN.")
                df['port'] = pd.to_numeric(df['port'], errors='coerce')
    else:
        logging.warning(f"No valid log entries found in '{log_file}'.")
        df = pd.DataFrame()

    logging.info(f"Parsed {len(df)} entries from '{log_file}'.")
    return df

def preprocess_system_logs(log_file):
    logs = []
    pattern = re.compile(r'(\w+)=([^\s]+)')

    try:
        with open(log_file, 'r') as file:
            for line in file:
                matches = pattern.findall(line)
                if matches:
                    log_entry = {key: value for key, value in matches}
                    logs.append(log_entry)
    except FileNotFoundError:
        logging.error(f"File '{log_file}' not found.")
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"Error processing system logs: {e}")
        return pd.DataFrame()

    if logs:
        df = pd.DataFrame(logs)
        if 'timestamp' in df.columns:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            except Exception as e:
                logging.error(f"Error converting 'timestamp' to datetime: {e}")
                df['timestamp'] = pd.NaT
    else:
        logging.warning(f"No valid log entries found in '{log_file}'.")
        df = pd.DataFrame()

    logging.info(f"Parsed {len(df)} entries from '{log_file}'.")
    return df

if __name__ == "__main__":
    # Parse and save Apache logs
    apache_df = parse_apache_logs(apache_log_path)
    apache_output_path = os.path.join(processed_dir, 'apache_access.csv')
    if not apache_df.empty:
        apache_df.to_csv(apache_output_path, index=False)
        logging.info(f"Apache logs parsed and saved to '{apache_output_path}'")

    # Parse and save Firewall logs
    firewall_df = preprocess_firewall_logs(firewall_log_path)
    firewall_output_path = os.path.join(processed_dir, 'firewall.csv')
    if not firewall_df.empty:
        firewall_df.to_csv(firewall_output_path, index=False)
        logging.info(f"Firewall logs parsed and saved to '{firewall_output_path}'")

    # Parse and save System logs
    system_df = preprocess_system_logs(system_log_path)
    system_output_path = os.path.join(processed_dir, 'system.csv')
    if not system_df.empty:
        system_df.to_csv(system_output_path, index=False)
        logging.info(f"System logs parsed and saved to '{system_output_path}'")
