
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class AdminAccount(db.Model):
    __tablename__ = 'admin_account'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    user = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

    # Account management
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
        default=lambda: datetime.now(timezone.utc)
    )
    session_version = db.Column(
    db.Integer,
    nullable=False,
    default=0
    )

    def __repr__(self):
        return f'<Admin {self.user}>'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
