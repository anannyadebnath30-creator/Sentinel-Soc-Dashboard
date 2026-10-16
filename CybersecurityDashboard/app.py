
from flask import (
    Flask, render_template, request, redirect,
    url_for, Response, flash, session
)
from functools import wraps
from datetime import datetime
from collections import Counter
from werkzeug.security import generate_password_hash, check_password_hash
from db_config import get_db_connection
import ipaddress
import csv
import io
import os

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "dev-only-change-this-secret-key"
)


# ----------------------------------------
# WELCOME PAGE
# ----------------------------------------

@app.route("/")
def welcome():
    if "user_id" in session:
        return redirect(url_for("index"))

    return render_template("welcome.html")


# ----------------------------------------
# DATABASE HELPERS
# ----------------------------------------

def fetch_logs():
    """Read security events from MySQL."""

    connection = get_db_connection()

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, event_time, ip_address,
                   event_type, event_status
            FROM security_logs
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()
        logs = []

        for row in rows:
            event_time = row["event_time"]

            logs.append({
                "id": row["id"],
                "ip": row["ip_address"],
                "event": row["event_type"],
                "status": row["event_status"],
                "time": event_time.strftime("%H:%M:%S")
                if event_time else ""
            })

        return logs

    finally:
        connection.close()


def fetch_incident_statuses():
    """Read incident statuses from MySQL."""

    connection = get_db_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT ip_address, incident_status
            FROM incidents
        """)

        return dict(cursor.fetchall())

    finally:
        connection.close()


def add_security_event(ip, event):
    """Save a security event to MySQL."""

    status = "Warning" if event == "Failed Login" else "Normal"
    connection = get_db_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO security_logs
                (event_time, ip_address, event_type, event_status)
            VALUES (%s, %s, %s, %s)
        """, (datetime.now(), ip, event, status))

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def seed_sample_data():
    """Insert demonstration events only if the log table is empty."""

    connection = get_db_connection()

    sample_events = [
        ("192.168.1.10", "Login Successful", "Normal", "09:00:00"),
        ("203.0.113.15", "Failed Login", "Warning", "09:01:00"),
        ("203.0.113.15", "Failed Login", "Warning", "09:02:00"),
        ("203.0.113.15", "Failed Login", "Warning", "09:03:00"),
        ("198.51.100.22", "Login Successful", "Normal", "09:04:00"),
        ("203.0.113.15", "Failed Login", "Warning", "09:05:00"),
        ("192.168.1.20", "Failed Login", "Warning", "09:06:00"),
    ]

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_logs")
        count = cursor.fetchone()[0]

        if count == 0:
            today = datetime.now().date()

            for ip, event, status, time_text in sample_events:
                event_time = datetime.combine(
                    today,
                    datetime.strptime(time_text, "%H:%M:%S").time()
                )

                cursor.execute("""
                    INSERT INTO security_logs
                        (event_time, ip_address, event_type, event_status)
                    VALUES (%s, %s, %s, %s)
                """, (event_time, ip, event, status))

            connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# ----------------------------------------
# LOGIN PROTECTION
# ----------------------------------------

def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access the dashboard.", "error")
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view


# ----------------------------------------
# REGISTER
# ----------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not username or not email:
            flash("Please complete all the required fields.", "error")
            return redirect(url_for("register"))

        if len(username) < 3 or len(username) > 50:
            flash("Username must be between 3 and 50 characters.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("The passwords do not match.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        connection = get_db_connection()

        try:
            cursor = connection.cursor()

            cursor.execute("""
                INSERT INTO users
                    (full_name, username, email, password_hash)
                VALUES (%s, %s, %s, %s)
            """, (full_name, username, email, password_hash))

            connection.commit()

            flash("Account created successfully! Please sign in.", "success")
            return redirect(url_for("login"))

        except Exception as error:
            connection.rollback()

            if getattr(error, "errno", None) == 1062:
                flash(
                    "That username or email is already registered.",
                    "error"
                )
            else:
                app.logger.exception("Registration failed")
                flash(
                    "Registration failed. Check the database connection "
                    "and try again.",
                    "error"
                )

            return redirect(url_for("register"))

        finally:
            connection.close()

    return render_template("register.html")


# ----------------------------------------
# LOGIN
# ----------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username_or_email = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_db_connection()

        try:
            cursor = connection.cursor(dictionary=True)

            cursor.execute("""
                SELECT id, full_name, username, email, password_hash
                FROM users
                WHERE username = %s OR email = %s
                LIMIT 1
            """, (username_or_email, username_or_email.lower()))

            user = cursor.fetchone()

        finally:
            connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]
            session["username"] = user["username"]

            flash("Welcome back!", "success")
            return redirect(url_for("index"))

        flash("Invalid username/email or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


# ----------------------------------------
# LOGOUT
# ----------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("welcome"))


# ----------------------------------------
# THREAT DETECTION
# ----------------------------------------

def is_failed_login(log):
    """Check whether an event represents a failed login."""

    event = str(log.get("event", "")).lower()
    status = str(log.get("status", "")).lower()

    failed_words = ("fail", "denied", "unsuccessful")

    event_is_failed = (
        "login" in event
        and any(word in event for word in failed_words)
    )

    status_is_failed = status in {
        "failed", "failure", "denied", "unsuccessful"
    }

    return event_is_failed or status_is_failed


def failed_login_counts(logs):
    """Count failed login events for every IP."""

    return Counter(
        log.get("ip", "Unknown")
        for log in logs
        if is_failed_login(log)
    )


def classify_severity(attempts):
    if attempts >= 10:
        return "Critical"
    elif attempts >= 6:
        return "High"
    elif attempts >= 3:
        return "Medium"
    else:
        return "Low"


def detect_threats(logs, statuses):
    """Create alerts for IPs with three or more failed logins."""

    counts = failed_login_counts(logs)
    alerts = []

    for ip, attempts in counts.items():
        if attempts >= 3:
            alerts.append({
                "ip": ip,
                "attempts": attempts,
                "severity": classify_severity(attempts),
                "status": statuses.get(ip, "Open")
            })

    return sorted(
        alerts,
        key=lambda alert: alert["attempts"],
        reverse=True
    )


def get_suspicious_ips(logs):
    counts = failed_login_counts(logs)
    return [ip for ip, count in counts.items() if count >= 3]


# ----------------------------------------
# MAIN DASHBOARD
# ----------------------------------------

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def index():

    if request.method == "POST":
        action = request.form.get("action", "")

        # Add a security event
        if action == "add":
            ip = request.form.get("ip", "").strip()
            event = request.form.get("event", "")

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                flash("Invalid IP address.", "error")
                return redirect(url_for("index"))

            if event not in ["Failed Login", "Login Successful"]:
                flash("Invalid event type.", "error")
                return redirect(url_for("index"))

            add_security_event(ip, event)
            return redirect(url_for("index"))

        # Update an incident status
        elif action == "update_status":
            ip = request.form.get("ip", "").strip()
            new_status = request.form.get("status", "")

            allowed_statuses = ["Open", "Investigating", "Resolved"]

            if new_status not in allowed_statuses:
                flash("Invalid incident status.", "error")
                return redirect(url_for("index"))

            logs = fetch_logs()

            if ip in get_suspicious_ips(logs):
                connection = get_db_connection()

                try:
                    cursor = connection.cursor()

                    cursor.execute("""
                        INSERT INTO incidents (ip_address, incident_status)
                        VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE
                            incident_status = %s
                    """, (ip, new_status, new_status))

                    connection.commit()

                except Exception:
                    connection.rollback()
                    raise

                finally:
                    connection.close()

            return redirect(url_for("index"))

        # Reset demonstration data
        elif action == "reset":
            connection = get_db_connection()

            try:
                cursor = connection.cursor()
                cursor.execute("DELETE FROM security_logs")
                cursor.execute("DELETE FROM incidents")
                connection.commit()

            except Exception:
                connection.rollback()
                raise

            finally:
                connection.close()

            seed_sample_data()
            return redirect(url_for("index"))

    # Read logs and incident statuses from MySQL
    security_logs = fetch_logs()
    incident_status = fetch_incident_statuses()

    total_logs = len(security_logs)

    failed_logins = sum(
        is_failed_login(log) for log in security_logs
    )

    successful_logins = sum(
        log["event"] == "Login Successful"
        for log in security_logs
    )

    alerts = detect_threats(security_logs, incident_status)
    suspicious_ips = get_suspicious_ips(security_logs)

    # Search and filter
    search = request.args.get("search", "").strip()
    selected_filter = request.args.get("filter", "all")

    filtered_logs = security_logs.copy()

    if selected_filter == "failed":
        filtered_logs = [
            log for log in filtered_logs
            if is_failed_login(log)
        ]

    elif selected_filter == "success":
        filtered_logs = [
            log for log in filtered_logs
            if log["event"] == "Login Successful"
        ]

    if search:
        filtered_logs = [
            log for log in filtered_logs
            if search.lower() in log["ip"].lower()
        ]

    # Chart data
    severity_counts = Counter(
        alert["severity"] for alert in alerts
    )

    severity_labels = ["Critical", "High", "Medium", "Low"]

    severity_values = [
        severity_counts.get(label, 0)
        for label in severity_labels
    ]

    return render_template(
        "index.html",
        logs=filtered_logs,
        total_logs=total_logs,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        suspicious_ips=suspicious_ips,
        alerts=alerts,
        search=search,
        selected_filter=selected_filter,
        severity_labels=severity_labels,
        severity_values=severity_values,
        full_name=session.get("full_name")
    )


# ----------------------------------------
# EXPORT CSV
# ----------------------------------------

@app.route("/export")
@login_required
def export_csv():

    security_logs = fetch_logs()
    incident_status = fetch_incident_statuses()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Event ID", "Time", "IP Address",
        "Event", "Severity", "Incident Status"
    ])

    counts = failed_login_counts(security_logs)
    suspicious_ips = get_suspicious_ips(security_logs)

    for log in security_logs:
        ip = log["ip"]
        attempts = counts.get(ip, 0)

        if ip in suspicious_ips:
            severity = classify_severity(attempts)
            status = incident_status.get(ip, "Open")
        elif is_failed_login(log):
            severity = "Low"
            status = "Not Applicable"
        else:
            severity = "Informational"
            status = "Not Applicable"

        writer.writerow([
            log["id"],
            log["time"],
            ip,
            log["event"],
            severity,
            status
        ])

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = (
        "attachment; filename=cybersecurity_report.csv"
    )

    return response


# ----------------------------------------
# START APPLICATION
# ----------------------------------------

if __name__ == "__main__":
    seed_sample_data()
    app.run(debug=True)
