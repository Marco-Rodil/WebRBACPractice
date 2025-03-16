from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime, timezone
from typing import Optional
from hashlib import md5
import enum
import sqlalchemy as sa
import sqlalchemy.orm as so
from app import db, login

@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))

class UserRole(enum.Enum):
    READER = 'reader'
    HR_MANAGER = 'hr manager'
    IT_SUPPORT = 'it support'
    EDITOR = 'editor'
    ADMIN = 'admin'

class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True, unique=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    role: so.Mapped[UserRole] = so.mapped_column(sa.Enum(UserRole), default=UserRole.READER) # SQLA Datatype
    about_me: so.Mapped[Optional[str]] = so.mapped_column(sa.String(140))
    last_seen: so.Mapped[Optional[datetime]] = so.mapped_column(default=lambda: datetime.now(timezone.utc))
    posts: so.WriteOnlyMapped['Post'] = so.relationship(back_populates='author')

    def get_role_string(self):
        return self.role.name

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def set_admin(self):
        self.role = UserRole.ADMIN

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'

    def can_view(self, other_user):
        if self.role == UserRole.ADMIN:
            return True
        if self.role == UserRole.HR_MANAGER and other_user.role in [UserRole.READER, UserRole.IT_SUPPORT, UserRole.EDITOR, UserRole.HR_MANAGER]:
            return True
        if self.role == UserRole.EDITOR and other_user.role in [UserRole.READER, UserRole.IT_SUPPORT, UserRole.EDITOR]:
            return True
        if self.role == UserRole.IT_SUPPORT and other_user.role in [UserRole.READER, UserRole.IT_SUPPORT]:
            return True
        if self.role == UserRole.READER and other_user.role == UserRole.READER:
            return True
        return False

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Post(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    body: so.Mapped[str] = so.mapped_column(sa.String(140))
    timestamp: so.Mapped[datetime] = so.mapped_column(index=True, default=lambda: datetime.now(timezone.utc))
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id), index=True)

    author: so.Mapped[User] = so.relationship(back_populates='posts')

    def __repr__(self):
        return '<Post {}>'.format(self.body)