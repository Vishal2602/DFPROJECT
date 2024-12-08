import pandas as pd
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Paths to processed log files
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
processed_dir = os.path.join(project_root, 'data', 'processed')

apache_file = os.path.join(processed_dir, 'apache_access.csv')
firewall_file = os.path.join(processed_dir, 'firewall.csv')
system_file = os.path.join(processed_dir, 'system.csv')
output_file = os.path.join(processed_dir, 'features.csv')

def load_csv(file_path, name):
    """Load a CSV file into a pandas DataFrame."""
    try:
        df = pd.read_csv(file_path)
        logging.info(f"Loaded {name} logs with {len(df)} entries.")
        return df
    except FileNotFoundError:
        logging.error(f"{name} logs not found: {file_path}")
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"Error loading {name} logs: {e}")
        return pd.DataFrame()

def extract_features(apache_df, firewall_df, system_df):
    """Extract features from the Apache, Firewall, and System logs."""
    logging.info("Extracting features from logs...")
    
    # Apache features
    if not apache_df.empty:
        apache_features = apache_df.copy()
        apache_features['hour'] = pd.to_datetime(apache_features['time']).dt.hour
        apache_agg = apache_features.groupby('ip').agg({
            'size': 'sum',
            'status': 'mean',
            'hour': 'mean'
        }).reset_index().rename(columns={'size': 'total_size', 'status': 'avg_status', 'hour': 'avg_hour'})
    else:
        logging.warning("Apache logs are empty. Skipping Apache feature extraction.")
        apache_agg = pd.DataFrame(columns=['ip', 'total_size', 'avg_status', 'avg_hour'])
    
    # Firewall features
    if not firewall_df.empty:
        firewall_agg = firewall_df.groupby('source_ip').agg({
            'port': 'nunique',
            'action': lambda x: (x == 'Deny').sum()
        }).reset_index().rename(columns={'source_ip': 'ip', 'port': 'unique_ports', 'action': 'deny_count'})
    else:
        logging.warning("Firewall logs are empty. Skipping Firewall feature extraction.")
        firewall_agg = pd.DataFrame(columns=['ip', 'unique_ports', 'deny_count'])
    
    # System features
    if not system_df.empty:
        system_agg = system_df.groupby('user').agg({
            'event_id': 'count',
            'severity': 'mean'
        }).reset_index().rename(columns={'user': 'ip', 'event_id': 'event_count', 'severity': 'avg_severity'})
    else:
        logging.warning("System logs are empty. Skipping System feature extraction.")
        system_agg = pd.DataFrame(columns=['ip', 'event_count', 'avg_severity'])
    
    # Merge features
    merged_features = apache_agg.merge(firewall_agg, on='ip', how='outer').merge(system_agg, on='ip', how='outer')
    merged_features.fillna(0, inplace=True)
    
    logging.info(f"Feature extraction complete. Total features extracted: {len(merged_features)}")
    return merged_features

if __name__ == "__main__":
    # Load processed log files
    apache_df = load_csv(apache_file, "Apache")
    firewall_df = load_csv(firewall_file, "Firewall")
    system_df = load_csv(system_file, "System")

    # Extract features
    features_df = extract_features(apache_df, firewall_df, system_df)

    # Save features to CSV
    if not features_df.empty:
        features_df.to_csv(output_file, index=False)
        logging.info(f"Features extracted and saved to '{output_file}'")
    else:
        logging.warning("No features were extracted. Check the input files.")
