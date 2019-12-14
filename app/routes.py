from flask import render_template, redirect, flash, url_for, request, g
from app import app, db
from app.forms import LoginForm, RegistrationForm, EditProfileForm, PostForm, ResetPasswordRequestForm, ResetPasswordForm, MessageForm, EditPostForm
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from app.models import User, Post, Message
from datetime import datetime
from app.email import send_password_reset_email
from flask_babel import _, get_locale



@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    """Funkcja wyświetlająca strone główną aplikacji wraz z postami obserwowanych użytkowników."""
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.post.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash(_('Succesfully added a post!'))
        return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    posts = current_user.followed_posts().paginate(
        page, app.config['POSTS_PER_PAGE'], False
    )
    next_url = url_for('index', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index.html', title=_("Home"), form=form, posts=posts.items,
                           next_url=next_url, prev_url=prev_url)


@app.route('/explore', methods=['GET'])
@login_required
def explore():
    """Funkcja wyświetlająca strone główną aplikacji wraz z postami wszystkich użytkowników."""
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.post.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Succesfully added a post!')
        return redirect(url_for('explore'))
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False
    )
    next_url = url_for('explore', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('explore', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index.html', title=_("Explore"), form=form, posts=posts.items,
                           next_url=next_url, prev_url=prev_url)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Funkcja wyświetlająca formularz logowania."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash(_('Invalid username or password'))
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title=_('Sign In'), form=form)


@app.route('/logout')
def logout():
    """Funkcja odpowiadająca za wylogowanie użytkownika z aplikacji."""
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Funkcja wyświetlająca formularz rejestracji użytkownika."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(_('Congratulations, you are now a registered user!'))
        return redirect(url_for('login'))
    return render_template('register.html', title=_('Register'), form=form)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    """Funkcja wyświetlająca formularz z żądaniem resetowania hasła."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash(_('Check your email for the instructions to reset your password'))
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title=_('Reset Password'), form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Funkcja wyświetlająca formularz resetowania hasła."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash(_('Your password has been reset.'))
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/user/<username>', methods=['GET'])
@login_required
def user(username):
    """Funkcja wyświetlająca profil użytkownika."""
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False
    )
    next_url = url_for('user', username=user.username, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('user', username=user.username, page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('user.html', user=user, posts=posts.items, title=username+_('\'s Profile'),
                           next_url=next_url, prev_url=prev_url)


@app.before_request
def before_request():
    """Funkcja pobierająca czas lokalny użytkownika przed wykonaniem żadania."""
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
    g.locale = str(get_locale())


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Funkcja wyświetlająca formularz edycji profilu."""
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        current_user.avatar_url = form.avatar.data
        db.session.commit()
        flash(_('Your changes have been saved!'))
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
        form.avatar.data = current_user.avatar_url
    return render_template('edit_profile.html', title=_('Edit Profile'), form=form)


@app.route('/follow/<username>')
@login_required
def follow(username):
    """Funkcja pozwalająca na obserwowanie innych użytkowników."""
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(_('User %(username)s not found.', username=username))
        return redirect(url_for('index'))
    if user == current_user:
        flash(_('You cannot follow yourself!'))
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash(_('You are following %(username)s!', username=username))
    return redirect(url_for('user', username=username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    """Funkcja pozwalająca na zaprzestanie obserwowania innych użytkowników."""
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(_('User %(username)s not found.', username=username))
        return redirect(url_for('index'))
    if user == current_user:
        flash(_('You cannot unfollow yourself!'))
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash(_('You are not following %(username)s.', username=username))
    return redirect(url_for('user', username=username))


@app.route('/user/<username>/popup')
def user_popup(username):
    """Funkcja tworząca 'wyskakujące' okno z informacjami o użytkowniku po najechaniu kursorem na nazwę użytkownika."""
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user_popup.html', user=user)


@app.route('/send_message/<recipient>', methods=['GET', 'POST'])
@login_required
def send_message(recipient):
    """Funkcja wyświetlająca formularz wysyłania wiadomości prywatnej."""
    user = User.query.filter_by(username=recipient).first_or_404()
    form = MessageForm()
    if form.validate_on_submit():
        msg = Message(author=current_user, recipient=user, body=form.message.data)
        db.session.add(msg)
        db.session.commit()
        flash(_('Your message has been sent.'))
        return redirect(url_for('user', username=recipient))
    return render_template('send_message.html', title=_('Send Message'), form=form, recipient=recipient)


@app.route('/messages/<username>')
@login_required
def conversation(username):
    """Funkcja wyświetlająca formularz wymienionych wiadomości z danym użytkownikiem."""
    current_user.last_message_read_time = datetime.utcnow()
    db.session.commit()
    form = MessageForm()
    messages = (Message.query.filter(Message.sender_id == current_user.id)).\
        union(Message.query.filter(Message.sender_id == db.session.query(User.id).filter(User.username == username))).\
        order_by(Message.timestamp.desc())
    return render_template('conversation.html', messages=messages.all(), form=form)


@app.route('/messages')
@login_required
def messages():
    """Funkcja wyświetlająca konwersacje użytkownika, w których bierze udział."""
    current_user.last_message_read_time = datetime.utcnow()
    db.session.commit()
    speakers = (db.session.query(User).distinct().filter(Message.recipient_id == current_user.id or Message.sender_id == current_user.id)).filter_by().all()
    return render_template('messages.html', speakers=speakers)


@app.route('/edit_post/<post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    """Funkcja wyświetlająca formularz edycji postów użytkownika."""
    post = Post.query.filter_by(id=post_id).all()
    form = EditPostForm()
    if form.validate_on_submit():
        post[0].body = form.body.data
        db.session.commit()
        flash(_('Your changes have been saved!'))
        return redirect(url_for('index'))
    elif request.method == 'GET':
        form.body.data = post[0].body
    return render_template('edit_post.html', title=_('Edit Post'), form=form)


@app.route('/delete_post/<post_id>')
@login_required
def delete_post(post_id):
    """Funkcja służąca do usuwania postów użytkownika."""
    post = Post.query.filter_by(id=post_id).first()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('index'))
