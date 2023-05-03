from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user, user_logged_in
from werkzeug.security import check_password_hash, generate_password_hash
import os
from datetime import datetime
from hashlib import md5
import requests
import smtplib


first_app = Flask(__name__)
first_app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db',
    "posts": 'sqlite:///posts.db'}
first_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
DATABASE='/tmp/flsite.db'
first_app.config['SECRET_KEY'] = 'wfo8r87F^F2FI9&PFOKWef'
#first_app.config.from_object(__name__)
#first_app.config.update(dict(DATABASE=os.path.join(first_app.root_path, 'flsite.db')))
db = SQLAlchemy(first_app)
manager = LoginManager(first_app)



class Post(db.Model):
    __bind_key__ = 'posts'
    post_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    publishing_date = db.Column(db.String(18), default=str(datetime.now))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tags = db.Column(db.String(10), nullable=False)
    login = db.Column(db.String(64), nullable=False)

    def __repr__(self):
        return '<Post {}>'.format(self.title)


class User(db.Model, UserMixin):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, index=True, unique=True)
    login = db.Column(db.String(64), nullable=False, index=True, unique=True)
    password = db.Column(db.String(300), nullable=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    color = db.Column(db.String(7), nullable=False, default='#000000')

    def __repr__(self):
        return '<User {}>'.format(self.login)



'''class Crypts(db.Model):
    __bind_key__ = 'crypts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(10), nullable=False, index=True, unique=True)
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    url = db.Column(db.String(500))

    def __repr__(self):
        return '<Crypts {}>'.format(self.name)
'''
@first_app.route('/')
@first_app.route('/index')
def index():
    #html = get_html(URL)
    #values = get_content(html.text)
    user_s = User.query.order_by(User.login).all()
    return render_template('index.html', datas=user_s)
    #, values=values)

@first_app.route('/search/<tags>/')
def search(tags):
    tag_posts = Post.query.filter_by(tags=tags).all()

@first_app.route('/news')
@login_required
def news():
    posts1 = Post.query.order_by(Post.text).all()
    print(posts1)
    #как отобразить никнеймы?
    return render_template('news.html', data=posts1)

@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@first_app.route('/channels')
def channels():
    pass

@first_app.route('/login', methods=['POST', 'GET'])
def login_page():
    if current_user.is_authenticated != True:
        login = request.form.get('username')
        password = request.form.get('psw')

        if login and password:
            user = User.query.filter_by(login=login).first()

            if user and check_password_hash(user.password, password):
                login_user(user)

                #next_page = request.args.get('next')

                return redirect(url_for('news'))
            else:
                flash('Логин или пароль неверны!', category='error')
        else:
            flash("Пожалуйста, введите почту, никнейм и пароль.", category='error')

        return render_template('login.html')
    return redirect(url_for('index'))

@first_app.route('/logout', methods=['POST', 'GET'])
def logout():
    logout_user()
    return redirect(url_for('index'))

@first_app.route('/register', methods=['POST', 'GET'])
def register():
    print(url_for('register'))
    if request.method == 'POST':
        email = request.form.get('email')
        #number = request.form.get('number')
        login = request.form.get('username')
        password = request.form.get('psw')
        password2 = request.form.get('psw2')
        if password != password2:
            flash('Пароли не совпадают!')
        elif User.query.filter_by(email=email).first() != None and User.query.filter_by(login=login).first() != None:
            print(User.query.filter_by(email=email))
            flash('Введенные Вами почта и никнейм уже существуют!', category='error')
        elif User.query.filter_by(email=email).first() != None:
            flash('Данная почта уже занята!', category='error')
        elif User.query.filter_by(login=login).first() != None:
            flash('Данный никнейм уже занят!', category='error')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(email=email, login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()
            send_mail(email, password)

            return redirect('/login')

    return render_template('register.html')


@first_app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response

'''@first_app.before_request
def before_request():
    g.user = current_user
    if g.user.is_authenticated():
        g.user.last_seen = datetime.now()
        db.session.add(g.user)
        db.session.commit()'''


@first_app.route('/profile')
@login_required
def profile():
    prof_data = User.query.get(current_user.get_id())
    #if login == current_user:
    return render_template('profile.html', data3=prof_data)

@first_app.route('/user/<login>')
@login_required
def user(login):
    print(User.query.filter_by(login=login).first())
    if current_user.get_id() == User.query.filter_by(login=login).first().get_id:
        return redirect('/profile')
    user_data = User.query.get(User.query.filter_by(login=login).first().get_id())
    return render_template('user.html', data6=user_data)

@first_app.route('/read/<int:post_id>')
@login_required
def item_read(post_id):
    item_r = Post.query.get(post_id)
    print(item_r)
    return render_template('read.html', data2=item_r)


@first_app.route('/read/<int:post_id>/delete')
@login_required
def item_delete(post_id):
    item_r = Post.query.get_or_404(post_id)

    try:
        if item_r.user_id == int(current_user.get_id()):
            db.session.delete(item_r)
            db.session.commit()
            return redirect('/news')
        else:
            return f"Неизвестная ссылка"
    except:
        return 'При удалении произошла ошибка'


@first_app.route('/read/<int:post_id>/update', methods=['POST', 'GET'])
@login_required
def item_update(post_id):
    post_upd = Post.query.get(post_id)
    if request.method == 'POST':
        post_upd.title = request.form['title']
        post_upd.text = request.form['text']

        try:
            if post_upd.user_id == int(current_user.get_id()):
                db.session.commit()
                return redirect('/profile')
            else:
                return f'Неизвестная ссылка'
        except:
            return 'При удалении произошла ошибка'
    else:
        return render_template('upd.html', post_upd=post_upd)


@first_app.route('/create', methods=['POST', 'GET'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        text = request.form['text']
        publishing_date = str(datetime.now())[0:19]
        user_id = current_user.id
        tags_1 = request.form['tags']
        login = User.query.get(current_user.id).login

        post = Post(title=title, text=text, publishing_date=publishing_date, user_id = user_id, tags=tags_1, login=login)

        try:
            db.session.add(post)
            db.session.commit()
            return redirect('/news')
        except:
            return 'Error!'
    else:
        return render_template('create.html')

#добавляем возможность редактирования профиля
@first_app.route('/profile/<int:id>/update', methods=['POST', 'GET'])
@login_required
def prof_update(id):
    user_upd = User.query.get(id)
    if request.method == 'POST':
        user_upd.login = request.form['login']
        user_upd.email = request.form['email']
        user_upd.color = request.form['color']

        try:
            if user_upd.id == int(current_user.get_id()):
                db.session.commit()
                return redirect('/profile')
            else:
                return f'Займись делом, а не взломом :3'
        except:
            return 'При изменении произошла ошибка'
    else:
        return render_template('user_upd.html', user_upd=user_upd)

@first_app.route('/contact', methods=['POST', 'GET'])
def contact():
    if request.method == 'POST':
        if len(request.form['username']) > 2:
            flash('Сообщение отправлено', category='success')
        else:
            flash('Ошибка отправки', category='error')

    return render_template('contact.html')

def send_mail(email, psw):
    sender_email = 'bloger147.178@gmail.com'
    password = 'ijfgwgvttsjthazw'
    subject = 'Your password'
    body = "Your password from www.bhc.com: " + str(psw)
    message = f'Subject: {subject}\n\n{body}'
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(sender_email, password)
    server.sendmail(sender_email, email, message)
    server.quit()

'''def get_html(url, params=''):
    r = requests.get(url, headers=HEADERS, params=params)
    return r


def get_content(html):
    soup = BeautifulSoup(html, 'html.parser')
    items = soup.find_all('table', class_='content_table')
    cards = []

    for item in items:
        cards.append(
            {
                'symbol':item.find('td', class_='cmc-table__cell cmc-table__\
                cell--sticky cmc-table__cell--sortable cmc-table__cell--left cmc-table__cell--sort-by__name'),#.find('di\
               # v').find('a', class_='cmc-table__column-name--symbol cmc-link').get_text(),
                'title':item.find('a', class_='cmc-table__column-name--name cmc-link')
            }
        )
    return cards[2]'''

'''@first_app.route('/admin', methods=['POST', 'GET'])
def admin():
    if current_user.is_authenticated == True:
        name = request.form.get('username')
        password = request.form.get('psw')
        if name == 'Winger' and password == 'Alexey13404' and current_user.get_id() == 1:
            return render_template('admin.html')
'''
@first_app.route('/about')
def about():
    return render_template('about.html')

'''def connect_db():
    conn = sqlite3.connect(first_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def create_db():
    db = connect_db()
    with first_app.open_resource('sq_db.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()'''

if __name__ == '__main__':
    first_app.run(debug=True)