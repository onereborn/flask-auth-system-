import os

class Config:
    SECRET_KEY = "supersecretkey"  
    SQLALCHEMY_DATABASE_URI = "sqlite:///users.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Flask-Mail config
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv("EMAIL_USER")   # set in environment
    MAIL_PASSWORD = os.getenv("EMAIL_PASS")   # set in environment
