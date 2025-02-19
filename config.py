from flask_mail import Mail
from flask_jwt_extended import JWTManager
mail = Mail()

def init_app(app):
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'vepkhistyaosaniproject@gmail.com'
    app.config['MAIL_PASSWORD'] = 'vymi jkng kwze aphz'
    app.config['MAIL_DEFAULT_SENDER'] = 'vepkhistyaosaniproject@gmail.com'

    mail.init_app(app)



app.config["JWT_SECRET_KEY"] = "sasssss123$"  # შეცვალე უსაფრთხო გასაღებით
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]  # ტოკენები იქნება Cookies-ში
app.config["JWT_COOKIE_SECURE"] = True  # მხოლოდ HTTPS-ზე მუშაობს
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # თუ CSRF დაცვა გჭირდება, აქ True

jwt = JWTManager(app)
