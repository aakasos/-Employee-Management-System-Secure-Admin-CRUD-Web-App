# Project Output

All screenshots were captured from the running application
(`python output/capture.py` regenerates them).

## 1. Admin login
![Login](01_login.png)

## 2. Authentication – wrong password rejected
![Login failed](02_login_failed.png)

## 3. Dashboard – employee list (Read) after creating records (Create)
![Dashboard](03_dashboard.png)

## 4. Validation – invalid input is rejected with field-level errors
![Validation](04_validation_errors.png)

## 5. Update – edit employee form
![Edit](05_edit_form.png)

## 6. Employee detail view
![Detail](06_employee_detail.png)

## 7. Automated test results
Full log: [`test_results.txt`](test_results.txt)

```
Ran 8 tests ... OK
```
| Test | Verifies |
|------|----------|
| dashboard_requires_login | Unauthenticated users are redirected to login |
| login_success_and_failure | Correct/incorrect credentials |
| post_without_csrf_is_rejected | CSRF protection (HTTP 400) |
| full_crud_cycle | Create → Read → Update → Delete |
| validation_rejects_bad_input | Bad name, email, phone, department, salary, future date |
| duplicate_email_rejected | Email uniqueness |
| sql_injection_attempt_is_harmless | Parameterised queries |
| logout_ends_session | Session cleared on logout |
