from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    link = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), default='General')
    country = db.Column(db.String(50), default='Global')  # <-- Nueva línea
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    confirmed = db.Column(db.Boolean, default=False)
    approved = db.Column(db.Boolean, default=False)
    pinned = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Group {self.name}>'

# Modelo para múltiples admins
class AdminUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<AdminUser {self.username}>'