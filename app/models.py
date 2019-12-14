from datetime import datetime
from hashlib import md5
from app import db, login, app
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from time import time
import jwt
import sqlalchemy

# Tabela obserwujących użytkowników.

followers = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)


msg = db.Table(
    'msg',
    db.Column('recipient_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('sender_id', db.Integer, db.ForeignKey('user.id')),
)


class User(UserMixin, db.Model):
    """Tabela przechowująca informacje o użytkownikach."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id',
                                    backref='author', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id',
                                        backref='recipient', lazy='dynamic')
    last_message_read_time = db.Column(db.DateTime)
    avatar_url = db.Column(db.String(200))

    def __repr__(self):
        """Wyświetlenie nazwy użytkownika."""
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        """Hashowanie hasła użytkownika."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Walidacja hasła użytkownika podczas logowania."""
        return check_password_hash(self.password_hash, password)

    def avatar(self, size, url=''):
        """Wygenerowanie avataru na podstawie adresu email użytkownika przy użyciu serwisu gravatar.com."""
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        self.avatar_url = url
        if self.avatar_url:
            return self.avatar_url
        else:
            return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
                digest, size)

    def follow(self, user):
        """Funkcjonalność obserwowania użytkowników."""
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        """Funkcjonalność zaprzestania obserwowania użytkowników."""
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        """Funkcja zwracająca liczbę obserwujących użytkownika."""
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        """Funkcja zwraca posty obserwowanych użytkowników."""
        followed = Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)).filter(
                followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())

    def get_reset_password_token(self, expires_in=600):
        """Funkcja generująca tokeny resetowania haseł."""
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        """Weryfikacja zgodności tokenu resetowania haseł."""
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

    def new_messages(self):
        """Funkcja zwraca ilość nowych nieprzeczytanych wiadomości."""
        last_read_time = self.last_message_read_time or datetime(1900, 1, 1)
        return Message.query.filter_by(recipient=self).filter(
            Message.timestamp > last_read_time).count()


@login.user_loader
def load_user(id):
    """Załadowanie użytkownika w aplikacji po logowaniu."""
    return User.query.get(int(id))


class Post(db.Model):
    """Tabela przechowująca informacje o postach zamieszczonych w aplikacji."""
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        """Wyświetlenie postu."""
        return '<Post {}>'.format(self.body)


class Message(db.Model):
    """Tabela przechowująca informacje o wysłanych wiadomościach."""
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        """Wyświetlenie wiadomości."""
        return '<Message {}>'.format(self.body)
