"""
Employee Management System
--------------------------
A Flask web application that lets administrators perform CRUD
(Create, Read, Update, Delete) operations on employee records.

Security features
  * Authentication  : session-based admin login, hashed passwords
  * Validation      : server-side validation of every field
  * CSRF protection : per-session token required on every POST
  * SQL injection   : parameterised queries only
  * Brute force     : temporary lock-out after repeated failed logins
"""
import os
import re
import secrets
import sqlite3
import time
from datetime import date, datetime
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEPARTMENTS = ["Engineering", "HR", "Finance", "Marketing", "Sales", "Operations", "Support"]
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300
PER_PAGE = 8

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^[6-9]\d{9}$")          # 10-digit Indian mobile number
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{1,59}$")


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
        DATABASE=os.path.join(BASE_DIR, "employees.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD", "Admin@123"),
    )
    if test_config:
        app.config.update(test_config)

    # ---------------------------------------------------------------- DB ---
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = sqlite3.connect(app.config["DATABASE"])
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS employees (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                email      TEXT UNIQUE NOT NULL,
                phone      TEXT NOT NULL,
                department TEXT NOT NULL,
                position   TEXT NOT NULL,
                salary     REAL NOT NULL CHECK (salary > 0),
                join_date  TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        exists = db.execute("SELECT 1 FROM admins WHERE username = ?",
                            (app.config["ADMIN_USERNAME"],)).fetchone()
        if not exists:
            db.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                       (app.config["ADMIN_USERNAME"],
                        generate_password_hash(app.config["ADMIN_PASSWORD"])))
        db.commit()
        db.close()

    init_db()

    # ---------------------------------------------------------- Security ---
    failed_logins = {}   # ip -> (count, first_failure_time)

    def csrf_token():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_hex(16)
        return session["_csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def protect_csrf():
        if request.method == "POST":
            sent = request.form.get("_csrf", "")
            if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
                abort(400, "Invalid or missing CSRF token.")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "admin_id" not in session:
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    # -------------------------------------------------------- Validation ---
    def validate_employee(form, employee_id=None):
        """Return (clean_data, errors)."""
        data = {k: form.get(k, "").strip() for k in
                ("name", "email", "phone", "department", "position", "salary", "join_date")}
        errors = {}

        if not NAME_RE.match(data["name"]):
            errors["name"] = "Name must be 2-60 letters (spaces, . ' - allowed)."

        data["email"] = data["email"].lower()
        if not EMAIL_RE.match(data["email"]):
            errors["email"] = "Enter a valid email address."
        else:
            row = get_db().execute("SELECT id FROM employees WHERE email = ?",
                                   (data["email"],)).fetchone()
            if row and row["id"] != employee_id:
                errors["email"] = "An employee with this email already exists."

        if not PHONE_RE.match(data["phone"]):
            errors["phone"] = "Phone must be a valid 10-digit mobile number."

        if data["department"] not in DEPARTMENTS:
            errors["department"] = "Select a valid department."

        if not (2 <= len(data["position"]) <= 60):
            errors["position"] = "Position must be 2-60 characters."

        try:
            salary = float(data["salary"])
            if not (0 < salary <= 10_000_000):
                raise ValueError
            data["salary"] = round(salary, 2)
        except ValueError:
            errors["salary"] = "Salary must be a positive number up to 10,000,000."

        try:
            jd = datetime.strptime(data["join_date"], "%Y-%m-%d").date()
            if jd > date.today():
                errors["join_date"] = "Joining date cannot be in the future."
        except ValueError:
            errors["join_date"] = "Enter a valid date (YYYY-MM-DD)."

        return data, errors

    # ------------------------------------------------------ Auth routes ---
    @app.route("/", methods=["GET"])
    def index():
        return redirect(url_for("dashboard" if "admin_id" in session else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr or "unknown"
            count, first = failed_logins.get(ip, (0, 0))
            if count >= MAX_FAILED_LOGINS and time.time() - first < LOCKOUT_SECONDS:
                flash("Too many failed attempts. Try again in a few minutes.", "danger")
                return render_template("login.html"), 429

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            admin = get_db().execute("SELECT * FROM admins WHERE username = ?",
                                     (username,)).fetchone()
            if admin and check_password_hash(admin["password_hash"], password):
                failed_logins.pop(ip, None)
                session.clear()
                session["admin_id"] = admin["id"]
                session["admin_name"] = admin["username"]
                flash(f"Welcome back, {admin['username']}!", "success")
                return redirect(url_for("dashboard"))

            if time.time() - first > LOCKOUT_SECONDS:
                count, first = 0, time.time()
            failed_logins[ip] = (count + 1, first or time.time())
            flash("Invalid username or password.", "danger")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # --------------------------------------------------- Employee CRUD ---
    @app.route("/dashboard")
    @login_required
    def dashboard():
        q = request.args.get("q", "").strip()
        dept = request.args.get("department", "")
        page = max(request.args.get("page", 1, type=int), 1)

        where, params = [], []
        if q:
            where.append("(name LIKE ? OR email LIKE ? OR position LIKE ?)")
            params += [f"%{q}%"] * 3
        if dept in DEPARTMENTS:
            where.append("department = ?")
            params.append(dept)
        clause = f"WHERE {' AND '.join(where)}" if where else ""

        db = get_db()
        total = db.execute(f"SELECT COUNT(*) FROM employees {clause}", params).fetchone()[0]
        rows = db.execute(
            f"SELECT * FROM employees {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [PER_PAGE, (page - 1) * PER_PAGE]).fetchall()
        stats = db.execute("SELECT COUNT(*) c, COALESCE(AVG(salary),0) a FROM employees").fetchone()
        pages = max((total + PER_PAGE - 1) // PER_PAGE, 1)
        return render_template("dashboard.html", employees=rows, q=q, dept=dept,
                               departments=DEPARTMENTS, page=page, pages=pages,
                               total=total, stats=stats)

    @app.route("/employees/new", methods=["GET", "POST"])
    @login_required
    def create_employee():                                    # CREATE
        if request.method == "POST":
            data, errors = validate_employee(request.form)
            if not errors:
                get_db().execute(
                    "INSERT INTO employees (name,email,phone,department,position,salary,join_date)"
                    " VALUES (:name,:email,:phone,:department,:position,:salary,:join_date)", data)
                get_db().commit()
                flash("Employee created successfully.", "success")
                return redirect(url_for("dashboard"))
            return render_template("form.html", mode="Add", emp=data, errors=errors,
                                   departments=DEPARTMENTS), 400
        return render_template("form.html", mode="Add", emp={}, errors={},
                               departments=DEPARTMENTS)

    @app.route("/employees/<int:emp_id>")
    @login_required
    def view_employee(emp_id):                                # READ (single)
        emp = get_db().execute("SELECT * FROM employees WHERE id = ?", (emp_id,)).fetchone()
        if emp is None:
            abort(404)
        return render_template("detail.html", emp=emp)

    @app.route("/employees/<int:emp_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_employee(emp_id):                                # UPDATE
        db = get_db()
        emp = db.execute("SELECT * FROM employees WHERE id = ?", (emp_id,)).fetchone()
        if emp is None:
            abort(404)
        if request.method == "POST":
            data, errors = validate_employee(request.form, employee_id=emp_id)
            if not errors:
                data["id"] = emp_id
                db.execute(
                    "UPDATE employees SET name=:name,email=:email,phone=:phone,"
                    "department=:department,position=:position,salary=:salary,"
                    "join_date=:join_date WHERE id=:id", data)
                db.commit()
                flash("Employee updated successfully.", "success")
                return redirect(url_for("view_employee", emp_id=emp_id))
            return render_template("form.html", mode="Edit", emp=data, errors=errors,
                                   departments=DEPARTMENTS, emp_id=emp_id), 400
        return render_template("form.html", mode="Edit", emp=dict(emp), errors={},
                               departments=DEPARTMENTS, emp_id=emp_id)

    @app.route("/employees/<int:emp_id>/delete", methods=["POST"])
    @login_required
    def delete_employee(emp_id):                              # DELETE
        db = get_db()
        cur = db.execute("DELETE FROM employees WHERE id = ?", (emp_id,))
        db.commit()
        if cur.rowcount == 0:
            abort(404)
        flash("Employee deleted.", "info")
        return redirect(url_for("dashboard"))

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(429)
    def error_page(err):
        return render_template("error.html", err=err), err.code

    return app


if __name__ == "__main__":
    # debug is off by default; set FLASK_DEBUG=1 for local development only
    create_app().run(host="127.0.0.1", port=5000,
                     debug=os.environ.get("FLASK_DEBUG") == "1")
