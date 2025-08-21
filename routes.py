from flask import render_template, request, redirect, url_for, session, flash, render_template_string
from db import get_db, hash_password
import os

stored_comments = []  # for stored XSS demo
tickets = []  # For demo purpose, storing tickets in memory
next_ticket_id = 1

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
    
    @app.route('/greet', methods=['GET'])
    def greet():
        name = request.args.get("name")
        if name:
            template = f"Hello {name}!"
            return render_template_string(template)
        return render_template('greet.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            hashed_password = hash_password(password)  # Hash the password before checking

            db = get_db()

            # Intentionally vulnerable to SQL Injection in the username field
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}' "
            print(f"Executing SQL Query: {query}")  # Debug the SQL query being executed

            result = db.execute(query).fetchone()
            if result:
                session['username'] = result[1]  # Log in as the specific user returned by the query
                session.pop('cart', None)  # Clear the cart on new login
                return redirect(url_for('home'))
            else:
                return render_template('error.html', message="Invalid credentials! Use SQL Injection payload in the username field.")
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('username', None)
        session.pop('cart', None)  # Clear the cart on logout
        return redirect(url_for('home'))

    @app.route('/search-user', methods=['GET', 'POST'])
    def search_user():
        
        if 'username' not in session:
            flash("You need to be logged in to search for users.")
            return redirect(url_for('login'))

        db = get_db()

        # Handle user actions
        if request.method == 'POST':
            if 'add_user' in request.form:
                # Add new user
                new_username = request.form['new_username']
                new_password = request.form['new_password']
                existing_user = db.execute("SELECT * FROM users WHERE username = ?", (new_username,)).fetchone()
                if existing_user:
                    flash("User already exists!")
                else:
                    hashed_password = hash_password(new_password)
                    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, hashed_password))
                    db.commit()
                    flash("User added successfully!")

            elif 'delete_user' in request.form:
                # Delete user
                user_id = request.form.get('user_id_to_delete')
                admin_user = db.execute("SELECT * FROM users WHERE id = ? AND username = 'admin'", (user_id,)).fetchone()
                if admin_user:
                    flash("Cannot delete the admin user!")
                else:
                    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
                    db.commit()
                    flash("User deleted successfully!")

            else:
                # Search user by ID
                user_id = request.form.get('user_id')
                try:
                    query = f"SELECT * FROM users WHERE id = {user_id}"
                    print(f"Executing SQL Query: {query}")
                    result = db.execute(query).fetchall()
                    if result:
                        user_data = result
                        return render_template('search_user.html', user_data=user_data)
                    else:
                        flash("No user found with that ID!")
                except Exception as e:
                    flash(f"An error occurred: {str(e)}")

        return render_template('search_user.html')

    @app.route('/products')
    def products():
        db = get_db()
        products_list = db.execute("SELECT * FROM products").fetchall()
        return render_template('products.html', products=products_list)

    @app.route('/add-to-cart/<int:product_id>')
    def add_to_cart(product_id):
        db = get_db()
        product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not product:
            flash('Product not found!')
            return redirect(url_for('products'))
        
        # Initialize cart if not present
        if 'cart' not in session:
            session['cart'] = []

        # Convert the product tuple to a dictionary for easier access in the cart
        session['cart'].append({'id': product[0], 'name': product[1], 'price': product[2]})
        flash(f"{product[1]} added to cart!")
        return redirect(url_for('products'))

    @app.route('/cart')
    def view_cart():
        cart = session.get('cart', [])
        total = sum(item['price'] for item in cart)
        return render_template('cart.html', cart=cart, total=total)

    @app.route('/checkout', methods=['POST'])
    def checkout():
        cart = session.get('cart', [])
        total = request.form.get('total')  # Vulnerable to parameter tampering

        # Check if the cart is empty before proceeding to checkout
        if not cart:
            flash("Your cart is empty. Please add items to your cart before checking out.")
            return redirect(url_for('products'))

        # Save order summary for display on the success page
        session['order_summary'] = cart
        session['order_total'] = total

        # Clear the cart after checkout
        session.pop('cart', None)

        # Redirect to the success page
        return redirect(url_for('checkout_success'))

    @app.route('/checkout-success')
    def checkout_success():
        order_summary = session.get('order_summary', [])
        order_total = session.get('order_total', 0)
        # Check if the order summary exists to prevent direct access to this page without completing checkout
        if not order_summary:
            flash("No order summary found. Please complete a checkout process.")
            return redirect(url_for('products'))
        return render_template('checkout_success.html', order_summary=order_summary, order_total=order_total)
    
    @app.route('/xss-demo', methods=['GET', 'POST'])
    def xss_demo():
        if 'username' not in session:
            flash("You must be logged in to access the XSS demo.", "danger")
            return redirect(url_for('login'))

        search = request.args.get('search')
        if request.method == 'POST':
            comment = request.form.get('comment', '')
            stored_comments.append(comment)  # store unsanitised comment
        return render_template(
            'xss_demo.html',
            search=search,
            comments=stored_comments,
        )
    
    
    @app.route('/rce', methods=['GET', 'POST'])
    def rce():
        if 'username' not in session:
            flash("You must be logged in to access the RCE demo.", "danger")
            return redirect(url_for('login'))

        output = None
        error = None

        if request.method == 'POST':
            user_input = request.form.get('url')

            if user_input:
                try:
                    # Command injection vulnerability: unsanitized user input is passed directly to the shell
                    command = f"nslookup {user_input}"  # Replace with `ping` or any network command as desired
                    output = os.popen(command).read()
                except Exception as e:
                    error = f"Error executing command: {str(e)}"
            else:
                flash("Please enter a valid URL.", "warning")

        return render_template('rce.html', output=output, error=error)
    
    @app.route('/create', methods=['GET', 'POST'])
    def create_ticket():
        global next_ticket_id
        if 'username' not in session:
            flash("You must be logged in to create a ticket.", "danger")
            return redirect(url_for('login'))

        if request.method == 'POST':
            username = session.get('username', 'anonymous')
            details = request.form.get('details', '')
            description = request.form.get('description', '')

            if not details or not description:
                flash("All fields are required.", "danger")
                return redirect(url_for('create_ticket'))

            tickets.append({
                'id': next_ticket_id,
                'username': username,
                'details': details,
                'description': description
            })
            tid = next_ticket_id
            next_ticket_id += 1
            return render_template('created.html', tid=tid)
        return render_template('create.html')

    @app.route('/admin/tickets')
    def view_tickets():
        return render_template('admin_tickets.html', tickets=tickets)
