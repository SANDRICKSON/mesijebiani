from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from datetime import datetime, timedelta
from flask_mail import Message
from extensions import app, mail, db
from models import User
from forms import RegisterForm, MessageForm, LoginForm, UpdateForm, ForgotPasswordForm, ResetPasswordForm

# 📌 Login Attempts შეზღუდვის მექანიზმი (IP-ებით)
login_attempts = {}

# 📌 Email ვერიფიკაციის ტოკენის გენერაცია
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 📌 პაროლის აღდგენის როუტი
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('პაროლის აღდგენა', sender="vepkkhistyaosaniproject@gmail.com", recipients=[user.email])
            msg.body = f"პაროლის აღსადგენად დააჭირეთ ამ ბმულს: {reset_url}"
            mail.send(msg)
            flash('ელ.ფოსტა გაგზავნილია!', 'success')
            return redirect(url_for('login'))
        else:
            flash('ამ ელ.ფოსტით მომხმარებელი არ მოიძებნა.', 'danger')
    return render_template('forgot_password.html', form=form, title="პაროლის აღდგენა")

# 📌 პაროლის განახლების როუტი
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1 საათი
    except (SignatureExpired, BadTimeSignature):
        flash('ბმული არასწორია ან ვადა გაუვიდა!', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('მომხმარებელი ვერ მოიძებნა!', 'danger')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('პაროლი წარმატებით განახლდა!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)

# 📌 ვერიფიკაციის იმეილის გაგზავნა
def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"დააჭირეთ ამ ბმულს თქვენი ემაილის ვერიფიკაციისთვის: {confirm_url}"

    msg = Message(subject=subject, sender="vepkkhistyaosaniproject@gmail.com", recipients=[user_email], body=message_body)
    mail.send(msg)

def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("ვერიფიკაციის ბმული არასწორია ან ვადა გაუვიდა!", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        db.session.commit()
        flash("თქვენი ემაილი წარმატებით ვერიფიცირდა!", "success")
    elif user and user.is_verified:
        flash("თქვენი ემაილი უკვე ვერიფიცირებულია!", "info")

    return redirect(url_for('login'))

# 📌 ავტორიზაციის როუტი - შეზღუდული მცდელობებით
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    ip = request.remote_addr  # ✅ სწორი დაშორება
    
    # თუ 5 მცდელობაა ბოლო 15 წუთში, დაბლოკე
    now = datetime.now()
    if ip in login_attempts:
        attempts, last_attempt = login_attempts[ip]
        if attempts >= 5 and now - last_attempt < timedelta(minutes=15):
            flash("ბევრი მცდელობა, სცადე მოგვიანებით!", "danger")
            return redirect(url_for("login"))
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_attempts[ip] = (0, now)  # ნულოვანი მცდელობა
            login_user(user)
            return redirect(url_for("index"))
        else:
            attempts = login_attempts.get(ip, (0, now))[0] + 1
            login_attempts[ip] = (attempts, now)
            flash("მომხმარებლის სახელი ან პაროლი არასწორია!", "danger")
    
    return render_template("login.html", form=form)

# 📌 რეგისტრაციის როუტი - ემაილის ვერიფიკაციის გაგზავნით
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            birthday=form.birthday.data,
            country=form.country.data,
            gender=form.gender.data,
            is_verified=False
        )
        db.session.add(user)
        db.session.commit()
        send_verification_email(user.email)
        flash("თქვენს ელფოსტაზე გაგზავნილია ვერიფიკაციის ბმული!", "info")
        return redirect(url_for("login"))
    
    return render_template("register.html", form=form, title="რეგისტრაცია")

# 📌 გამოსვლის როუტი
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
