from flask import render_template, request, redirect, url_for, session
from db import get_db

def configure_routes(app):
    @app.teardown_appcontext
    def teardown_db(exception):
        get_db().close()

    @app.route('/')
    def home():
        if 'username' in session:
            username = session['username']
            return render_template('home.html', username=username)
        return render_template('home.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            db = get_db()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            print(f"Executing SQL Query: {query}")
            result = db.execute(query).fetchone()
            if result:
                session['username'] = username
                return redirect(url_for('home'))
            else:
                return render_template('error.html', message="Invalid credentials!")
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('username', None)
        return redirect(url_for('home'))

    @app.route('/search-user', methods=['GET', 'POST'])
    def search_user():
        if 'username' not in session:
            return redirect(url_for('login'))

        if request.method == 'POST':
            user_id = request.form['user_id']
            db = get_db()
            try:
                query = f"SELECT * FROM users WHERE id = {user_id}"
                print(f"Executing SQL Query: {query}")
                result = db.execute(query).fetchall()
                if result:
                    user_data = '<br>'.join([f"ID: {row[0]}, Username: {row[1]}, Password: {row[2]}" for row in result])
                    return render_template('search_user.html', user_data=user_data)
                else:
                    return render_template('error.html', message="No user found with that ID!")
            except Exception as e:
                return render_template('error.html', message=f"An error occurred: {str(e)}")

        return render_template('search_user.html')
        