import os
import click
from app import app


@app.cli.group()
def translate():
    """Komendy translacji i lokalizacji."""
    pass


@translate.command()
@click.argument('lang')
def init(lang):
    """Dodanie nowego języka."""
    if os.system('pybabel extract -F babel.cfg -k _l -o messages.pot .'):
        raise RuntimeError('extract command failed')
    if os.system(
            'pybabel init -i messages.pot -d app/translations -l ' + lang):
        raise RuntimeError('init command failed')
    os.remove('messages.pot')


@translate.command()
def update():
    """Aktualizacja wszystkich języków."""
    if os.system('pybabel extract -F babel.cfg -k _l -o messages.pot .'):
        raise RuntimeError('extract command failed')
    if os.system('pybabel update -i messages.pot -d app/translations'):
        raise RuntimeError('update command failed')
    os.remove('messages.pot')


@translate.command()
def compile():
    """Kompilacja wszystkich języków."""
    if os.system('pybabel compile -d app/translations'):
        raise RuntimeError('compile command failed')
