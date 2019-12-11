from app import app, db, cli
from app.models import User, Post, Message


@app.shell_context_processor
def make_shell_context():
    """Łatwy dostęp do informacji o instancji bazy danych oraz jej tabelach."""
    return {'db': db, 'User': User, 'Post': Post, 'Message': Message}
