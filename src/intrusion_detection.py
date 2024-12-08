import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Paths to processed features and model directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
processed_dir = os.path.join(project_root, 'data', 'processed')
model_dir = os.path.join(project_root, 'models')

features_file = os.path.join(processed_dir, 'features.csv')
model_file = os.path.join(model_dir, 'random_forest_model.pkl')

def train_model(features_file, model_file):
    """Train the intrusion detection model."""
    try:
        df = pd.read_csv(features_file)
    except FileNotFoundError:
        logging.error(f"Features file not found: {features_file}")
        return
    except Exception as e:
        logging.error(f"Error reading features file: {e}")
        return

    # Add synthetic labels if missing
    if 'label' not in df.columns:
        logging.warning("'label' column missing. Adding synthetic labels for demonstration.")
        df['label'] = (df['deny_count'] > 0).astype(int)  # Mark rows with deny_count > 0 as anomalies
        df.to_csv(features_file, index=False)  # Save updated features with labels

    # Prepare training data
    X = df.drop(['ip', 'label'], axis=1)
    y = df['label']

    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # Train Random Forest Classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    logging.info("Training Random Forest model...")
    clf.fit(X_train, y_train)

    # Evaluate Model
    y_pred = clf.predict(X_test)
    logging.info("Model evaluation:")
    print(classification_report(y_test, y_pred))

    # Save the model
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(clf, model_file)
    logging.info(f"Model saved to '{model_file}'")

def predict_anomalies(features_file, model_file):
    """Predict anomalies using the trained model."""
    try:
        df = pd.read_csv(features_file)
        model = joblib.load(model_file)
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return
    except Exception as e:
        logging.error(f"Error loading file: {e}")
        return

    # Add synthetic labels for consistency during prediction
    if 'label' not in df.columns:
        logging.warning("'label' column not found. Adding synthetic labels for prediction.")
        df['label'] = 0  # Default to 0 (benign) for all rows

    # Prepare features for prediction
    X = df.drop(['ip', 'label'], axis=1)
    predictions = model.predict(X)
    df['predicted_label'] = predictions

    # Identify anomalies
    anomalies = df[df['predicted_label'] == 1]
    logging.info(f"Anomalies detected: {len(anomalies)}")
    print(anomalies[['ip', 'predicted_label']])

if __name__ == "__main__":
    # Train the model
    train_model(features_file, model_file)

    # Predict anomalies
    predict_anomalies(features_file, model_file)
