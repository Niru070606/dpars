import hmac
import secrets

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app import db
from app.models.admin_account import AdminAccount


protected_bp = Blueprint("protected", __name__)


# ==========================================
# CSRF TOKEN HELPER
# ==========================================
def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)

    return session["_csrf_token"]


# ==========================================
# ADMIN SESSION VALIDATION
# ==========================================
@protected_bp.before_request
def check_admin_session():
    admin_id = session.get("admin_id")

    # Require an authenticated session
    if not admin_id:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("auth.login"))

    # Retrieve the account from the database
    admin = db.session.get(AdminAccount, admin_id)

    # Reject missing or inactive accounts
    if not admin or not admin.is_active:
        session.clear()
        flash(
            "Your account is inactive or your session has expired.",
            "warning",
        )
        return redirect(url_for("auth.login"))

    # Reject outdated sessions
    if session.get("session_version") != admin.session_version:
        session.clear()
        flash(
            "Your session has expired. Please log in again.",
            "warning",
        )
        return redirect(url_for("auth.login"))

    # Refresh session information
    session["admin_user"] = admin.user
    session["admin_email"] = admin.email


# ==========================================
# PROTECTED DASHBOARD
# ==========================================
@protected_bp.route("/protected/dashboard", methods=["GET"])
def protected():
    return render_template("protected/protected_dashboard.html")


# ==========================================
# MANAGE REGISTRAR ACCOUNTS
# ==========================================
@protected_bp.route("/protected/accounts", methods=["GET"])
def manage_accounts():
    accounts = AdminAccount.query.order_by(
        AdminAccount.id.asc()
    ).all()

    active_count = AdminAccount.query.filter_by(
        is_active=True
    ).count()

    inactive_count = AdminAccount.query.filter_by(
        is_active=False
    ).count()

    return render_template(
        "protected/manage_accounts.html",
        accounts=accounts,
        active_count=active_count,
        inactive_count=inactive_count,
        current_admin_id=session.get("admin_id"),
        csrf_token=get_csrf_token(),
    )

# ==========================================
# DEACTIVATE REGISTRAR ACCOUNT
# ==========================================
@protected_bp.route(
    "/protected/accounts/<int:account_id>/deactivate",
    methods=["POST"],
)
def deactivate_account(account_id):
    import hmac

    # Validate CSRF token
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("_csrf_token", "")

    if (
        not submitted_token
        or not expected_token
        or not hmac.compare_digest(submitted_token, expected_token)
    ):
        flash("Invalid request token. Please try again.", "error")
        return redirect(url_for("protected.manage_accounts"))

    # Prevent self-deactivation
    current_admin_id = session.get("admin_id")

    if account_id == current_admin_id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("protected.manage_accounts"))

    # Find account
    account = db.session.get(AdminAccount, account_id)

    if not account:
        flash("Registrar account not found.", "error")
        return redirect(url_for("protected.manage_accounts"))

    if not account.is_active:
        flash("This account is already inactive.", "warning")
        return redirect(url_for("protected.manage_accounts"))

    # Prevent deactivating the last active account
    active_count = AdminAccount.query.filter_by(
        is_active=True
    ).count()

    if active_count <= 1:
        flash(
            "You cannot deactivate the last active account.",
            "error",
        )
        return redirect(url_for("protected.manage_accounts"))

    try:
        account.is_active = False
        account.session_version += 1
        db.session.commit()

        flash(
            f"Account '{account.user}' has been deactivated.",
            "success",
        )

    except SQLAlchemyError:
        db.session.rollback()
        flash(
            "A database error occurred while deactivating the account.",
            "error",
        )

    return redirect(url_for("protected.manage_accounts"))


@protected_bp.route(
    "/protected/accounts/<int:account_id>/activate",
    methods=["POST"]
)
def activate_account(account_id):
    import hmac

    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("_csrf_token", "")

    if (
        not submitted_token
        or not expected_token
        or not hmac.compare_digest(submitted_token, expected_token)
    ):
        flash("Invalid request token. Please try again.", "error")
        return redirect(url_for("protected.manage_accounts"))

    current_admin_id = session.get("admin_id")

    account = db.session.get(AdminAccount, account_id)

    if account is None:
        flash("Account not found.", "error")
        return redirect(url_for("protected.manage_accounts"))

    if account.is_active:
        flash("This account is already active.", "error")
        return redirect(url_for("protected.manage_accounts"))

    try:
        account.is_active = True

        # Ensure old sessions remain invalid after reactivation.
        account.session_version += 1

        db.session.commit()

        flash(
            f"Account '{account.user}' has been activated.",
            "success"
        )

    except SQLAlchemyError:
        db.session.rollback()
        flash(
            "A database error occurred while activating the account.",
            "error"
        )

    return redirect(url_for("protected.manage_accounts"))



# ==========================================
# CHANGE REGISTRAR ACCOUNT PASSWORD
# ==========================================
@protected_bp.route(
    "/protected/accounts/<int:account_id>/change-password",
    methods=["POST"],
)
def change_account_password(account_id):
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("_csrf_token", "")

    if (
        not submitted_token
        or not expected_token
        or not hmac.compare_digest(submitted_token, expected_token)
    ):
        flash("Invalid request token. Please try again.", "error")
        return redirect(url_for("protected.manage_accounts"))

    # Prevent changing your own password through this admin action.
    current_admin_id = session.get("admin_id")

    if account_id == current_admin_id:
        flash(
            "You cannot change your own password from this action.",
            "error",
        )
        return redirect(url_for("protected.manage_accounts"))

    account = db.session.get(AdminAccount, account_id)

    if account is None:
        flash("Registrar account not found.", "error")
        return redirect(url_for("protected.manage_accounts"))

    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not new_password or not confirm_password:
        flash("Please fill in both password fields.", "error")
        return redirect(url_for("protected.manage_accounts"))

    if len(new_password) < 6:
        flash(
            "Password must be at least 6 characters long.",
            "error",
        )
        return redirect(url_for("protected.manage_accounts"))

    if new_password != confirm_password:
        flash("The passwords do not match.", "error")
        return redirect(url_for("protected.manage_accounts"))

    try:
        account.set_password(new_password)

        # Invalidate sessions using the previous password.
        account.session_version += 1

        db.session.commit()

        flash(
            f"Password updated for account '{account.user}'.",
            "success",
        )

    except SQLAlchemyError:
        db.session.rollback()
        flash(
            "A database error occurred while changing the password.",
            "error",
        )

    return redirect(url_for("protected.manage_accounts"))

# ==========================================
# ADD REGISTRAR ACCOUNT — EXISTING ROUTE
# ==========================================
@protected_bp.route(
    "/protected/add-access",
    methods=["GET", "POST"],
)
def add_access():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Validate required fields
        if not username or not email or not password:
            flash("Please fill in all fields.", "error")
            return render_template("protected/add_access.html")

        # Validate username length
        if len(username) < 3:
            flash(
                "Username must be at least 3 characters long.",
                "error",
            )
            return render_template("protected/add_access.html")

        # Validate password length
        if len(password) < 6:
            flash(
                "Password must be at least 6 characters long.",
                "error",
            )
            return render_template("protected/add_access.html")

        # Check whether the username already exists
        existing_username = AdminAccount.query.filter_by(
            user=username
        ).first()

        if existing_username:
            flash("Username already exists.", "error")
            return render_template("protected/add_access.html")

        # Check whether the email already exists
        existing_email = AdminAccount.query.filter_by(
            email=email
        ).first()

        if existing_email:
            flash("Email address already exists.", "error")
            return render_template("protected/add_access.html")

        # Create the registrar account
        new_admin = AdminAccount(
            user=username,
            email=email,
            is_active=True,
            session_version=0,
        )

        # Hash the password using your model method
        new_admin.set_password(password)

        try:
            db.session.add(new_admin)
            db.session.commit()

            flash(
                "Registrar account created successfully.",
                "success",
            )
            return redirect(url_for("protected.add_access"))

        except IntegrityError:
            db.session.rollback()
            flash(
                "The username or email is already in use.",
                "error",
            )
            return render_template("protected/add_access.html")

        except SQLAlchemyError:
            db.session.rollback()
            flash(
                "A database error occurred while creating the account.",
                "error",
            )
            return render_template("protected/add_access.html")

    return render_template("protected/add_access.html")
