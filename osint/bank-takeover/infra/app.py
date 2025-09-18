import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, g, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = 'users.db'
app.secret_key = 'CaRdkF1BGa'

# setup dummy database with credientials that are not meant to be used
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        # Add admin user if not exists
        cursor.execute('SELECT * FROM accounts WHERE username = ?', ('admin',))
        if cursor.fetchone() is None:
            password_hash = generate_password_hash("2D5D5E9A2B14683455158EBD62776")
            cursor.execute('INSERT INTO accounts (username, password_hash) VALUES (?, ?)', ('admin', password_hash))
            db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# routes
@app.route('/')
def home():
    return redirect(url_for('login'))

# login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT password_hash FROM accounts WHERE username = ?', (username,))
        result = cursor.fetchone()

        if result and check_password_hash(result[0], password):
            return redirect(url_for('account'))
        else:
            error = "Invalid credentials, Maybe you forgot your password?"
    return render_template('login.html', error=error)

# forgot password page, actual osint challenge logic
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        message ="Please fill out all the fields to gain access to your account"
        return render_template('forgot_password.html', message=message)

    if request.method == 'POST':
        name = request.form.get('name', '')
        birthday = request.form.get('birthday', '')
        car = request.form.get('car', '').lower()
        email = request.form.get('email', '').lower()
        number = request.form.get('number', '')
        song = request.form.get('song', '').lower()

        print(name,email,birthday,number,car,song) #debugging
        # correct answers
        correct_name = 'Ford Prefect'
        correct_email = 'praxibetel.ix1@gmail.com'
        alt_email = 'praxibetelix1@gmail.com'
        correct_birthday = '1979-10-12'
        correct_car_keyword = 'delorean'
        correct_number = '42'
        correct_song = 'crypt walk'

        # check answers
        if (name == correct_name and 
            email in (correct_email, alt_email) and
            birthday == correct_birthday and
            correct_car_keyword in car and
            number == correct_number and
            song == correct_song):
            session['from_forgot_password'] = True
            return render_template('account.html')
        else:
            message = "At least one of your answers is Incorrect. Please try again."
    return render_template('forgot_password.html', message=message)

#account page displays flag when successful "login"
@app.route('/account')
def account():
    if not session.pop('from_forgot_password', None):  
        abort(403)  # Forbidden
    return render_template('account.html')


if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0",port=5000,debug=True)
