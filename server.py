from flask import Flask,render_template,redirect,request,session,flash
import re
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL   

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = "validation"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route('/')
def index():
        return render_template("index.html")

@app.route('/register', methods=['POST', 'GET'])
def register():
        if request.form:
            is_valid = True
            if len(request.form['first_name']) < 3:
                is_valid = False
                flash("First name must be at least 2 characters!")
                return redirect('/')
            if len(request.form['last_name']) < 3:
                is_valid = False
                flash("Last name must be at least 2 characters!")
                return redirect('/')
            if not EMAIL_REGEX.match(request.form['email']):
                is_valid = False    # test whether a field matches the pattern
                flash("Invalid email address!")
                return redirect('/')
            if len(request.form['password']) < 8:
                is_valid = False
                flash("Password must be at least 8 characters")
                return redirect('/')
            if request.form['password'] != request.form['confirm_password']:
                is_valid = False
                flash("Passwords do not match!")
                return redirect('/')
            else:
                pw_hash = bcrypt.generate_password_hash(request.form['password'])
                query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password_hash)s);"
                data = {
                    "first_name":request.form['first_name'],
                    "last_name":request.form['last_name'],
                    "email":request.form['email'],
                    "password_hash":pw_hash
                }
                user_id = connectToMySQL('login-and-registration').query_db(query, data)
                if user_id is False:
                    flash("This email is already a registered user!")
                    return redirect('/')
                session['user_id'] = user_id
                print(user_id)
                return redirect(f"/success/{user_id}")
        else:
            return redirect("/")

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.form:
        is_valid = True
        if not EMAIL_REGEX.match(request.form['email']):
            flash("Invalid email address!")
            return redirect('/')
        else:
            query = "SELECT * FROM users WHERE email = %(email)s;"
            data = {
                "email":request.form['email']
            }
            users = connectToMySQL('login-and-registration').query_db(query, data)
            if len(users) != 1:
                is_valid=False
                flash("Email not registered")
                return redirect('/')  
            if not bcrypt.check_password_hash(users[0]['password'], request.form['password']):
                is_valid=False
                flash("Incorrect Password")
                return redirect('/')  
            session['user_id'] = users[0]['id']
            user_id = users[0]['id']
            print(users)
            return redirect(f"/success/{user_id}")
    else:
        return render_template("index.html")

@app.route('/success/<int:user_id>', methods=["GET"])
def success(user_id):
        if "user_id" not in session:
            return redirect('/')
        query = "SELECT * FROM users WHERE id = %(user_id)s;"
        data = {
            "user_id":user_id
        }
        users = connectToMySQL('login-and-registration').query_db(query, data)
        return render_template("success.html", users=users)

@app.route('/logout', methods=['POST'])
def logout():
        session.clear()
        return redirect('/')
        
if __name__ == "__main__":
    app.run(debug=True)