
# 📘 **Intrusion Detection System (IDS)**

A comprehensive system for analyzing **Apache, Firewall, and System logs** to detect and flag **suspicious activities**. The system leverages **rule-based logic** and **machine learning** to identify potential threats. It generates **visual reports** in PDF format and provides key insights into network activity.

---

## 📋 **Table of Contents**
1. [**Project Overview**](#-project-overview)
2. [**System Requirements**](#-system-requirements)
3. [**Installation**](#-installation)
4. [**Usage Instructions**](#-usage-instructions)
5. [**Project Structure**](#-project-structure)
6. [**File Descriptions**](#-file-descriptions)
7. [**Troubleshooting**](#-troubleshooting)
8. [**Contributing**](#-contributing)
9. [**License**](#-license)

---

## 📄 **Project Overview**
The **Intrusion Detection System (IDS)** analyzes logs from **Apache, Firewall, and System activity** to identify abnormal patterns. It processes large log files, extracts key features, and builds a **Random Forest Classifier** to predict whether an IP is **suspicious**. The system generates:
- **PNG visualizations** for request trends and deny counts.
- **PDF reports** with summaries, results, and conclusions.
- **Suspicious log entries** for detailed review.

---

## 💻 **System Requirements**
- **Operating System**: Windows, macOS, or Linux
- **Python Version**: Python 3.8 or higher
- **Hardware Requirements**: 
  - 4 GB RAM
  - 2 GB Disk Space
  - At least **1 GB free space** for large log files

**Required Libraries**
- **Python Libraries**:
  ```
  pandas
  matplotlib
  seaborn
  fpdf
  scikit-learn
  joblib
  ```

Install these libraries via pip:
```bash
pip install -r requirements.txt
```

---

## 🚀 **Installation**
To set up the project, follow these steps:

### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/username/IntrusionDetectionSystem.git
cd IntrusionDetectionSystem
```

### **2️⃣ Set Up Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### **3️⃣ Install Requirements**
Install required libraries listed in `requirements.txt`:
```bash
pip install -r requirements.txt
```

### **4️⃣ Set Up Directory Structure**
Ensure the following structure exists:
```
log-file-analysis/
├── data/
│   ├── raw/
│   └── processed/
├── reports/
├── models/
└── src/
```
Make sure to have a **`data/raw/`** directory with your log files (e.g., Apache, Firewall, System logs).

---

## 📚 **Usage Instructions**
To run the system and generate reports, follow these steps.

### **1️⃣ Data Preprocessing**
Run the **data_preprocessing.py** script to clean and process log files.
```bash
python src/data_preprocessing.py
```

### **2️⃣ Feature Extraction**
Extract features from the log files by running:
```bash
python src/feature_extraction.py
```

### **3️⃣ Train Model & Detect Intrusions**
Train the **Random Forest classifier** and identify **suspicious IPs**.
```bash
python src/intrusion_detection.py
```

### **4️⃣ Save Suspicious Logs**
Save the suspicious log entries to a separate file for analysis.
```bash
python src/save_suspicious_logs.py
```

### **5️⃣ Generate PDF Report**
Generate a **PDF report** summarizing the analysis, results, and conclusions.
```bash
python src/reporting.py
```

**Expected Outputs**
- **PDF Report**: `reports/Intrusion_Detection_Report.pdf`
- **Visualizations**: 
  - `reports/request_trends.png`
  - `reports/top_deny_ips.png`
- **Suspicious Logs**: 
  - `reports/suspicious_apache_logs.csv`
  - `reports/suspicious_firewall_logs.csv`
  - `reports/suspicious_system_logs.csv`

---

## 📂 **Project Structure**
```
log-file-analysis/
├── data/
│   ├── raw/
│   └── processed/
├── reports/
├── models/
├── requirements.txt
├── README.md
└── src/
    ├── data_preprocessing.py
    ├── feature_extraction.py
    ├── intrusion_detection.py
    ├── save_suspicious_logs.py
    └── reporting.py
```

---

## 📄 **File Descriptions**
| **File Name**          | **Purpose**                             |
|-----------------------|------------------------------------------|
| **`data_preprocessing.py`** | Processes raw Apache, Firewall, and System logs. |
| **`feature_extraction.py`**  | Extracts key features from logs for ML training. |
| **`intrusion_detection.py`** | Trains and evaluates a Random Forest ML model.   |
| **`save_suspicious_logs.py`**| Filters and saves suspicious log entries.       |
| **`reporting.py`**           | Generates a PDF report with images and insights.|

---

## 🔧 **Troubleshooting**
| **Issue**           | **Cause**                    | **Solution**                              |
|---------------------|----------------------------|------------------------------------------|
| File not found       | Log files are missing      | Ensure `data/raw` has the required logs.  |
| UnicodeEncodeError  | FPDF requires ASCII text   | Use `-` instead of `•` in PDF generation. |
| Model load failed    | Missing model file         | Retrain the model using `intrusion_detection.py`. |
| Pandas KeyError     | Missing columns in CSV     | Ensure correct headers are in logs.      |

---

## 🤝 **Contributing**
We welcome contributions! To contribute:
1. **Fork the repository**.
2. **Create a branch** for your feature.
3. **Submit a pull request** with detailed explanations of changes made.

---

## 📝 **License**
This project is licensed under the **MIT License**. See `LICENSE` for more information.
