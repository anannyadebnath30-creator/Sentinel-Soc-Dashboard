# 🛡️ SENTINEL SOC — Cybersecurity Threat Monitoring Dashboard

A web-based cybersecurity dashboard designed to simulate a Security Operations Center (SOC). The project helps users monitor security logs, identify suspicious activities, track security incidents, and visualize threat-related information through a centralized interface.

## 📌 Project Overview

**SENTINEL SOC** is a student project developed to explore how security monitoring dashboards work in a Security Operations Center.

It combines a Flask web application with a MySQL database to demonstrate security log monitoring, incident tracking, user authentication, and basic threat detection.

## ✨ Features

- 🔐 **User Authentication:** User registration and login.
- 📊 **Security Dashboard:** Centralized view of security monitoring information.
- 🔎 **Security Log Monitoring:** View and search security log records.
- 🚨 **Threat Detection:** Demonstration of basic rules for identifying suspicious activities.
- 📋 **Incident Management:** View and track security incidents.
- 📈 **Data Visualization:** Display security-related information using charts.
- 📥 **CSV Export:** Export supported log data for further analysis.
- 🗄️ **MySQL Integration:** Store application and security monitoring data.
- 🎨 **Web Interface:** User interface built with HTML and CSS.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Application logic |
| Flask | Web framework |
| MySQL | Database management |
| HTML5 | Web page structure |
| CSS3 | Styling and layout |
| JavaScript | Client-side interactions |
| Chart.js | Data visualization |
| Jinja2 | Dynamic HTML templates |

## 📁 Project Structure

```text
CybersecurityDashboard/
│
├── app.py
├── db_config.py
├── README.md
│
├── templates/
│   ├── welcome.html
│   ├── login.html
│   ├── register.html
│   └── index.html
│
└── static/
    ├── style.css
    └── welcome.css
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/sentinel-soc-dashboard.git
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Open the project folder

```bash
cd sentinel-soc-dashboard
```

### 3. Install the required Python packages

```bash
python -m pip install flask mysql-connector-python
```

### 4. Configure the MySQL database

1. Start your MySQL server.
2. Create a database named `sentinel_soc`.
3. Configure the database connection in `db_config.py`.
4. Ensure the database tables required by the application are created.

**Important:** Update the database configuration for your own environment. Never upload database passwords or other secrets to GitHub.

### 5. Run the application

```bash
python app.py
```

### 6. Open the website

Visit the following address in your browser:

```text
http://127.0.0.1:5000/
```

## 🔍 Project Objectives

- Understand the fundamentals of Security Operations Center monitoring.
- Learn how web applications can support security log analysis.
- Practice Python and Flask application development.
- Integrate a web application with a MySQL database.
- Explore basic threat detection and incident management concepts.
- Develop practical cybersecurity and software development skills.

## 🔒 Security Considerations

This project is intended for educational and demonstration purposes.

- Passwords should be stored using secure password hashing.
- Database credentials should be kept private.
- Authentication and session management should be configured securely.
- Input validation should be applied to user-provided data.
- The dashboard's threat detection logic should not be considered a replacement for a production-grade security monitoring platform.

## 🚧 Limitations

- Threat detection depends on the rules and sample data implemented in the application.
- The dashboard is a demonstration project and may not receive live security events.
- It is not a replacement for enterprise SIEM tools.
- Production deployment would require additional security testing, monitoring, and hardening.

## 🚀 Future Enhancements

- Integrate live log sources.
- Add advanced threat detection rules.
- Integrate tools such as Splunk or the Elastic Stack.
- Add severity-based alerts and notifications.
- Implement role-based access control.
- Improve reporting and incident investigation features.

## 🎓 Learning Outcomes

Through this project, I aim to strengthen my understanding of:

- Python programming and Flask.
- Database connectivity using MySQL.
- Web development fundamentals.
- Security logs and incident monitoring.
- Basic threat detection concepts.
- Building and documenting a cybersecurity portfolio project.

## 👩‍💻 Author

**Ananya**  
MCA Student  
Institute of Management and Entrepreneurship Development (IMED)  
Bharati Vidyapeeth (Deemed to be University), Pune

## ⚠️ Disclaimer

This project is developed for educational purposes. It is intended to demonstrate basic cybersecurity monitoring concepts and should not be used as a production security monitoring solution without appropriate testing and security improvements.
