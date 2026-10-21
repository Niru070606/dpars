from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

def create_app():
        app = Flask(__name__)

        app.config['SQLALCHEMY_DATABASE_URI']=\
        'mysql+pymysql://root:StrongPassword123@127.0.0.1:3306/dpars_db'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

        # Needed for Flask `flash()` and sessions
        app.config['SECRET_KEY'] = 'dev-secret-key-change-me'

        app.config['MAIL_SERVER'] = 'smtp.gmail.com'
        app.config['MAIL_PORT'] = 587
        app.config['MAIL_USE_TLS'] = True
        app.config['MAIL_USE_SSL'] = False
        app.config['MAIL_DEBUG'] = True
        app.config['MAIL_USERNAME'] = 'dparspup@gmail.com'
        app.config['MAIL_PASSWORD'] = 'dpars070606.....'

        mail.init_app(app)


        db.init_app(app)
        migrate.init_app(app, db)

        from app.models.admin_account import AdminAccount

        from app.controllers.login_controllers import auth_bp
        from app.controllers.public_controllers import public_bp
        from app.controllers.protected_controllers import protected_bp

        app.register_blueprint(auth_bp)
        app.register_blueprint(public_bp)
        app.register_blueprint(protected_bp)
     
        return app
