from flask import render_template
from app import app


@app.route('/')
@app.route('/index')
def index():
    user = {'username': 'Damian'}
    posts = [
        {
            'author': {'username': 'John'},
            'body': 'What a beautiful day!'
        },
        {
            'author': {'username': 'Susan'},
            'body': 'Had a great coffee this morning!'
        }
    ]
    return render_template('index.html', title="Home", user=user, posts=posts)
