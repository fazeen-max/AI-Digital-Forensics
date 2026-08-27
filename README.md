🛡️ AI Digital Forensics

An AI-powered security investigation and threat analysis platform built with Python, Flask, Pandas, Scikit-learn, and ReportLab.

The system analyzes security log evidence, uses a machine-learning model to classify potential threats, provides an interactive forensic dashboard, maintains investigation history, and generates professional PDF investigation reports.

---

📌 Project Overview

AI Digital Forensics is a web-based forensic investigation platform designed to assist in analyzing security events and identifying potentially suspicious or malicious activity.

The application provides a centralized dashboard where security events can be analyzed and reviewed through:

- AI-based threat classification
- Security event analysis
- Threat statistics and distribution
- Interactive event investigation
- Investigation history
- Evidence upload
- Professional investigation reports
- PDF report generation and download

The project is designed as an educational and prototype security-analysis platform and is not intended to replace professional SIEM, EDR, or incident-response systems.

---

🎯 Objectives

The main objectives of the project are to:

1. Analyze security log evidence automatically.
2. Apply machine-learning techniques to classify security events.
3. Identify normal, suspicious, and malicious activity.
4. Provide an easy-to-use forensic investigation dashboard.
5. Preserve investigation history for later review.
6. Generate structured investigation reports.
7. Provide downloadable PDF reports for forensic documentation.
8. Demonstrate the practical use of AI/ML in digital forensics.

---

🚀 Key Features

🤖 AI Threat Detection

The system uses a machine-learning threat classifier to analyze security events and generate:

- AI prediction
- AI confidence score
- Final threat classification
- Forensic reasoning

🛡️ Threat Classification

Security events are categorized into three primary levels:

Classification| Description
🟢 NORMAL| Activity that does not currently indicate suspicious behavior
🟡 SUSPICIOUS| Activity requiring additional investigation
🔴 MALICIOUS| Activity classified as potentially harmful

📊 Security Dashboard

The dashboard provides an overview of analyzed security activity, including:

- Total events
- Normal events
- Suspicious events
- Malicious events
- Threat distribution
- AI confidence
- Recent security events

The threat distribution also displays the percentage contribution of each threat category.

🔎 Interactive Investigation

Security events can be selected from the event table to display detailed investigation information, including:

- Timestamp
- Username
- Source IP
- Event type
- Threat classification
- AI confidence
- Forensic reason

📁 Evidence Upload

Users can upload security-log CSV files through the Evidence Analysis interface.

The application validates the required security-log structure before analysis.

Required columns include:

timestamp
username
source_ip
event_type

📚 Investigation History

Completed investigations are recorded and displayed in the Investigation History section.

Stored information includes:

- Investigation date
- Evidence filename
- Total events
- Normal events
- Suspicious events
- Malicious events

📄 Professional Reports

The system provides a dedicated investigation report preview containing:

- Evidence information
- Investigation statistics
- Detailed findings
- Threat classifications
- AI confidence scores

📥 PDF Report Generation

Investigation reports can be generated as professional PDF documents using ReportLab.

The PDF contains:

- AI Digital Forensics title
- Investigation summary
- Event statistics
- Detailed investigation findings
- Threat classifications
- Confidence values

---

🧠 Machine Learning

The project uses a Random Forest classifier for security threat classification.

The machine-learning workflow includes:

1. Preparing the training dataset
2. Preprocessing security-event information
3. Training the Random Forest model
4. Evaluating model performance
5. Saving the trained classifier
6. Loading the model during investigation
7. Generating predictions for analyzed events

The trained model is stored in:

models/threat_classifier.pkl

---

🏗️ System Architecture

The application follows a modular architecture:

Security Log CSV
       │
       ▼
Evidence Upload
       │
       ▼
Data Validation
       │
       ▼
Log Analysis
       │
       ▼
AI Threat Classifier
       │
       ▼
Threat Prediction
       │
       ▼
Forensic Investigation Engine
       │
       ├──────────────► Dashboard
       │
       ├──────────────► Investigation History
       │
       └──────────────► Investigation Report
                              │
                              ▼
                         PDF Generation

---

🖥️ Application Workflow

1. Open Dashboard
        ↓
2. Upload Security Evidence
        ↓
3. Validate CSV File
        ↓
4. Analyze Security Events
        ↓
5. Generate AI Threat Predictions
        ↓
6. Display Investigation Results
        ↓
7. Save Investigation History
        ↓
8. Review Dashboard Statistics
        ↓
9. Open Report Preview
        ↓
10. Download PDF Investigation Report

---

🧰 Technology Stack

Backend

- Python
- Flask
- Pandas

Machine Learning

- Scikit-learn
- Random Forest Classifier

Data Processing

- Pandas
- CSV-based security logs

Frontend

- HTML5
- CSS3
- JavaScript
- Jinja2 Templates

Reporting

- ReportLab
- PDF generation

Development

- Visual Studio Code
- Git
- GitHub
- Python Virtual Environment

---

📂 Project Structure

AI-Digital-Forensics/
│
├── analysis/
│   ├── investigation_engine.py
│   ├── log_analyzer.py
│   ├── predict_threat.py
│   ├── train_model.py
│   └── README.md
│
├── dataset/
│   └── threat_training.csv
│
├── history/
│   └── investigations.json
│
├── models/
│   └── threat_classifier.pkl
│
├── static/
│   ├── css/
│   │   └── dashboard.css
│   │
│   └── js/
│       └── dashboard.js
│
├── templates/
│   ├── dashboard.html
│   ├── history.html
│   └── report.html
│
├── uploads/
│   └── uploaded security evidence
│
├── app.py
├── requirements.txt
└── README.md

«The ".venv" directory is a local Python virtual environment and should not be included in the GitHub repository.»

---

⚙️ Installation

1. Clone the repository

git clone <YOUR-GITHUB-REPOSITORY-URL>

2. Open the project directory

cd AI-Digital-Forensics

3. Create a virtual environment

python -m venv .venv

4. Activate the virtual environment

Windows

.venv\Scripts\activate

5. Install dependencies

pip install -r requirements.txt

---

▶️ Running the Application

Start the Flask application:

python app.py

Then open the application in your browser:

http://127.0.0.1:5000/

---

📊 Using the Dashboard

Dashboard

The main dashboard displays:

- Security statistics
- Threat distribution
- Recent security events
- Event investigation interface

Evidence

Use the Evidence section to upload a security-log CSV file.

Investigations

Use Investigations to review previously analyzed evidence.

Reports

Use Reports to:

1. Preview the current investigation.
2. Review investigation findings.
3. Download the investigation as a PDF.

---

🧪 Testing

The application was tested across the primary investigation workflow:

Evidence Upload
      ↓
CSV Validation
      ↓
AI Analysis
      ↓
Results
      ↓
Dashboard
      ↓
Event Investigation
      ↓
Investigation History
      ↓
Report Preview
      ↓
PDF Download

The implemented workflow was verified to successfully:

- Process uploaded security logs
- Analyze security events
- Generate threat classifications
- Display event statistics
- Display investigation details
- Store investigation history
- Generate report previews
- Generate downloadable PDF reports

---

🔐 Security Considerations

This project is intended for educational and controlled testing environments.

Recommended improvements for production deployment include:

- Secure file-upload validation
- File-size restrictions
- Filename sanitization
- Authentication and authorization
- HTTPS
- Secure session configuration
- Database-backed investigation storage
- Stronger logging and auditing
- Production-grade Flask deployment
- Additional security testing

---

⚠️ Limitations

The current version has several limitations:

- Analysis is based on uploaded security-log evidence.
- It does not perform live network packet capture.
- It is not a complete enterprise SIEM solution.
- Machine-learning accuracy depends on the quality and representativeness of the training dataset.
- Investigation history is currently stored locally.
- The application is primarily designed as an academic/prototype project.

---

🔮 Future Enhancements

Possible future improvements include:

- Real-time network monitoring
- Live intrusion detection
- Additional machine-learning algorithms
- Deep-learning based threat detection
- Real-time security alerts
- Email notifications
- Advanced forensic visualizations
- Search and filtering of investigations
- User authentication
- Role-based access control
- Database integration
- Automated incident-response workflows
- Threat-intelligence integration
- Advanced PDF report customization

---

📈 Project Status

Status: Completed Prototype

The current implementation includes the core AI-assisted security analysis, forensic dashboard, investigation history, evidence upload, report preview, and PDF reporting workflow.

---

👩‍💻 Development

This project was developed as an academic cybersecurity and artificial-intelligence project to demonstrate the practical application of:

- Artificial Intelligence
- Machine Learning
- Digital Forensics
- Network Security
- Web Development
- Security Event Analysis

---

📜 License

This project is intended for educational and academic purposes.

You may modify and extend the project for learning, research, and development purposes.

---

⭐ Acknowledgment

This project demonstrates how AI and machine learning can be integrated with digital-forensics workflows to assist security analysts in identifying, investigating, and documenting potentially suspicious security activity.

AI Digital Forensics — Analyze. Investigate. Document.