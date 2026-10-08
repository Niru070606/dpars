from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import db
from app.models.admin_account import AdminAccount


protected_bp = Blueprint('protected', __name__)


@protected_bp.route('/protected/dashboard')
def protected():

    if not session.get('admin_id'):
        flash(
            'Please log in to access the dashboard.',
            'warning'
        )
        return redirect(url_for('auth.login'))

    return render_template('protected/protected_dashboard.html')


@protected_bp.route('/protected/add-access', methods=['GET', 'POST'])
def add_access():

    if not session.get('admin_id'):
        flash(
            'Please log in to access this page.',
            'warning'
        )
        return redirect(url_for('auth.login'))

    if request.method == 'POST':

        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Check required fields
        if not username or not email or not password:
            flash(
                'Please fill in all fields.',
                'error'
            )
            return render_template('protected/add_access.html')

        # Check password length
        if len(password) < 6:
            flash(
                'Password must be at least 6 characters long.',
                'error'
            )
            return render_template('protected/add_access.html')

        # Check if username already exists
        existing_username = AdminAccount.query.filter_by(
            user=username
        ).first()

        if existing_username:
            flash(
                'Username already exists.',
                'error'
            )
            return render_template('protected/add_access.html')

        # Check if email already exists
        existing_email = AdminAccount.query.filter_by(
            email=email
        ).first()

        if existing_email:
            flash(
                'Email address already exists.',
                'error'
            )
            return render_template('protected/add_access.html')

        # Create account
        admin = AdminAccount(
            user=username,
            email=email
        )

        # Hash password
        admin.set_password(password)

        # Save to database
        try:
            db.session.add(admin)
            db.session.commit()

            flash(
                'Registrar account successfully created.',
                'success'
            )

            return redirect(url_for('protected.add_access'))

        except Exception:
            db.session.rollback()

            flash(
                'Something went wrong while creating the account.',
                'error'
            )

            return render_template(
                'protected/add_access.html'
            )

    return render_template('protected/add_access.html')