# 👥 Employee Management System

A secure Flask web application that lets **administrators** perform **CRUD**
(Create, Read, Update, Delete) operations on employee records, with proper
**validation** and **authentication** to protect sensitive employee data.

## Features

| Area | Details |
|------|---------|
| CRUD | Add, view, edit and delete employees |
| Authentication | Admin login with hashed passwords (PBKDF2 via Werkzeug), session-protected routes, logout |
| Validation | Server-side checks on name, email (format + unique), phone (10-digit), department, position, salary, joining date |
| Security | CSRF tokens on every POST, parameterised SQL (no SQL injection), login lock-out after 5 failed attempts, security headers (CSP, X-Frame-Options, nosniff) |
| Usability | Search, department filter, pagination, dashboard stats |
| Testing | 8 automated tests covering auth, CSRF, validation, CRUD and SQL-injection attempts |

## Tech stack
Python 3.9+, Flask, SQLite, Jinja2 templates, plain CSS.

## Project structure
```
employee-management-system/
├── app.py              # Main program (routes, DB, auth, validation)
├── templates/          # HTML pages (login, dashboard, form, detail, error)
├── static/style.css    # Styling
├── tests/test_app.py   # Automated tests
├── output/             # Screenshots + test results (see output/OUTPUT.md)
├── requirements.txt
└── README.md
```

## Getting started

```bash
# 1. Clone
git clone https://github.com/<your-username>/employee-management-system.git
cd employee-management-system

# 2. (Recommended) virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py
```
Open **http://127.0.0.1:5000** and log in.

Default admin (created on first run): `admin` / `Admin@123`

> ⚠️ **Change these before any real use.** Set your own credentials and secret key:
> ```bash
> export ADMIN_USERNAME=youradmin
> export ADMIN_PASSWORD='a-strong-password'
> export SECRET_KEY='long-random-string'
> ```
> (Windows PowerShell: `$env:ADMIN_PASSWORD="..."`). The admin is created only
> when the database is first initialised, so delete `employees.db` to re-seed.

## Run the tests
```bash
python -m unittest discover -s tests -v
```

## Routes

| Method | URL | Purpose | Auth |
|--------|-----|---------|------|
| GET/POST | `/login` | Admin login | No |
| POST | `/logout` | Log out | Yes |
| GET | `/dashboard` | List, search, filter, paginate | Yes |
| GET/POST | `/employees/new` | **Create** | Yes |
| GET | `/employees/<id>` | **Read** | Yes |
| GET/POST | `/employees/<id>/edit` | **Update** | Yes |
| POST | `/employees/<id>/delete` | **Delete** | Yes |

## Validation rules
- **Name:** 2–60 letters (spaces, `.`, `'`, `-` allowed)
- **Email:** valid format, unique (case-insensitive)
- **Phone:** 10-digit mobile number starting with 6–9
- **Department:** must be one of the predefined list
- **Salary:** positive number, max 10,000,000
- **Joining date:** valid date, not in the future

## Production notes
Run behind HTTPS with a production server (e.g. `gunicorn "app:create_app()"`),
set `SESSION_COOKIE_SECURE=True`, and use a strong `SECRET_KEY`.

## Output
Screenshots and test results are in [`output/OUTPUT.md`](output/OUTPUT.md).

## License
MIT
