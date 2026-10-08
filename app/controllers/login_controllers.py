import random
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app
)
from app import db, mail
from app.models.admin_account import AdminAccount
from flask_mail import Message

# Authentication Blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def role():
    return render_template('portal/selection.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle admin/registrar authentication."""

    # If already logged in
    if session.get('admin_id'):
        try:
            return redirect(url_for('protected.dashboard'))
        except Exception:
            return redirect('/protected/dashboard')

    if request.method == 'POST':

        # Get login credentials
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Validate input
        if not username or not password:
            flash(
                'Please enter your username/email and password.',
                'error'
            )
            return render_template('auth/login.html')

        # Find account using username OR email
        admin = AdminAccount.query.filter(
            (AdminAccount.user == username) |
            (AdminAccount.email == username)
        ).first()

        # Check password against stored hash
        if admin and admin.check_password(password):

            # Store session
            session.clear()

            session['admin_id'] = admin.id
            session['admin_user'] = admin.user
            session['admin_email'] = admin.email
            session['is_admin'] = True

            flash('Welcome back!', 'success')

            # Redirect to dashboard
            next_url = request.args.get('next')

            try:
                target_url = next_url or url_for('protected.dashboard')
            except Exception:
                target_url = '/protected/dashboard'

            return redirect(target_url)

        else:

            flash(
                'Invalid username/email or password.',
                'error'
            )

    return render_template('auth/login.html')


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset requests."""

    if request.method == 'POST':

        # Get recovery email from the form
        email = request.form.get('email', '').strip().lower()

        # Validate email
        if not email:
            flash(
                'Please enter your registered email address.',
                'error'
            )
            return render_template('auth/forgot_password.html')

        # Find admin account
        admin = AdminAccount.query.filter_by(email=email).first()

        if admin:

            # Generate a 6-digit OTP
            otp_code = f'{random.randint(100000, 999999)}'

            # Store reset information in session
            session['reset_email'] = email
            session['reset_otp'] = otp_code
            session['otp_verified'] = False

            # Development testing
            message = Message(
                subject='D-PARS Password Reset OTP',
                sender= current_app.config['MAIL_USERNAME'],
                recipients=[email]
            )

            message.body = f"""
            Hello,

            Your D-PARS password reset verification code is:

            {otp_code}

            This code is required to reset your password.

            If you did not request a password reset, you can ignore this email.

            D-PARS
            PUP Unisan
            """

            mail.send(message)

            flash(
                'A 6-digit verification code has been sent. '
                'Please verify to continue.',
                'info'
            )

            return redirect(url_for('auth.verify'))

        else:

            # Do not reveal whether the email exists
            flash(
                'If that email is registered in our system, '
                'a verification code was sent.',
                'info'
            )

            return redirect(url_for('auth.verify'))

    return render_template('auth/forgot_password.html')

@auth_bp.route('/verify', methods=['GET', 'POST'])
def verify():
    """Verify OTP code for password reset."""

    # Get reset email from session
    reset_email = session.get('reset_email')

    # Make sure a reset request exists
    if not reset_email:
        flash(
            'Session expired or invalid reset request. '
            'Please start again.',
            'warning'
        )
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':

        # Get OTP entered by the user
        entered_code = request.form.get('otp', '').strip()

        # Get OTP stored in session
        stored_otp = session.get('reset_otp')

        # Validate input
        if not entered_code:
            flash(
                'Please enter the verification code.',
                'error'
            )
            return render_template(
                'auth/verify.html',
                email=reset_email
            )

        # Check OTP
        if entered_code == stored_otp:

            # Mark OTP as verified
            session['otp_verified'] = True

            # Remove OTP so it cannot be reused
            session.pop('reset_otp', None)

            flash(
                'Verification successful! '
                'You may now set a new password.',
                'success'
            )

            return redirect(url_for('auth.reset_password'))

        else:

            flash(
                'Invalid verification code. '
                'Please check and try again.',
                'error'
            )

    return render_template(
        'auth/verify.html',
        email=reset_email
    )


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Handle new password submission."""

    # Make sure the user successfully verified the OTP
    if not session.get('otp_verified') or not session.get('reset_email'):
        flash(
            'Unauthorized password reset attempt. '
            'Please verify your email first.',
            'error'
        )
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':

        # Get passwords from the form
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validate empty fields
        if not password or not confirm_password:
            flash(
                'Please fill in both password fields.',
                'error'
            )
            return render_template('auth/reset_password.html')

        # Check if passwords match
        if password != confirm_password:
            flash(
                'Passwords do not match.',
                'error'
            )
            return render_template('auth/reset_password.html')

        # Check minimum password length
        if len(password) < 6:
            flash(
                'Password must be at least 6 characters long.',
                'error'
            )
            return render_template('auth/reset_password.html')

        # Get the email stored during password recovery
        email = session.get('reset_email')

        # Find the account
        admin = AdminAccount.query.filter_by(email=email).first()

        if not admin:
            flash(
                'Account not found. Please contact the administrator.',
                'error'
            )
            return redirect(url_for('auth.forgot_password'))

        # Update password
        admin.set_password(password)

        try:
            db.session.commit()

        except Exception:
            db.session.rollback()

            flash(
                'Something went wrong while resetting your password. '
                'Please try again.',
                'error'
            )

            return render_template('auth/reset_password.html')

        # Clear password-reset session data
        session.pop('reset_email', None)
        session.pop('reset_otp', None)
        session.pop('otp_verified', None)

        flash(
            'Your password has been successfully reset! '
            'Please log in.',
            'success'
        )

        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html')


@auth_bp.route('/logout')
def logout():
    """Log out the current admin and clear session."""
    session.clear()
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('auth.login'))

