from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object("config.Config")

db = SQLAlchemy(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    verified = db.Column(db.Boolean, default=False)

# Home
@app.route("/")
def home():
    return render_template("login.html")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for("register"))
        
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        # Send verification email
        token = s.dumps(email, salt="email-confirm")
        link = url_for("verify_email", token=token, _external=True)
        msg = Message("Confirm your account", sender=app.config["MAIL_USERNAME"], recipients=[email])
        msg.body = f"Click the link to verify your account: {link}"
        mail.send(msg)

        flash("Check your email for verification link", "info")
        return redirect(url_for("home"))
    return render_template("register.html")

# Email verification
@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = s.loads(token, salt="email-confirm", max_age=3600)  # 1 hour expiry
    except:
        flash("The verification link is invalid or has expired", "danger")
        return redirect(url_for("home"))
    
    user = User.query.filter_by(email=email).first()
    if user:
        user.verified = True
        db.session.commit()
        flash("Your account has been verified!", "success")
        return redirect(url_for("home"))
    return redirect(url_for("home"))

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.verified:
                flash("Please verify your email first!", "warning")
                return redirect(url_for("home"))
            return render_template("dashboard.html", user=user)
        flash("Invalid credentials", "danger")
    return render_template("login.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
