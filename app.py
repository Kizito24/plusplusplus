from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash  # Updated import
import bcrypt
from datetime import datetime

app = Flask(__name__)

# Set up the secret key for sessions
app.secret_key = 'your_secret_key_here'

# MongoDB setup
app.config["MONGO_URI"] = "mongodb://localhost:27017/your_database"
mongo = PyMongo(app)

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({'_id': session['user_id']})
    if user and user.get('is_admin', False):
        return redirect(url_for('admin_dashboard'))

    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = mongo.db.users.find_one({'email': email})

        if user:
            # Ensure the password is encoded before checking
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                session['user_id'] = str(user['_id'])
                session['user_name'] = user['name']
                session['is_admin'] = user['is_admin']

                # Redirect based on whether the user is admin or not
                if user['is_admin']:
                    return redirect(url_for('add_question'))
                else:
                    return redirect(url_for('home'))
            else:
                return "Invalid password. Please try again."

        return "User not found. Please register."

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        # Hash the password with bcrypt after encoding it to bytes
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # Password encoding here
        
        # Check if the email already exists in the database
        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            return "Email already exists, please log in."

        # Check if user is an admin (by looking at the name)
        is_admin = name.endswith('ADMIN')

        # Insert new user into the database
        mongo.db.users.insert_one({'email': email, 'password': hashed_password, 'name': name, 'is_admin': is_admin})
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({'_id': session['user_id']})
    if not user or not user.get('is_admin', False):
        return redirect(url_for('home'))  # Only admin can access this route

    return render_template('admin_dashboard.html')

@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    questions = mongo.db.questions.find()
    if request.method == 'POST':
        score = 0
        total = len(questions)
        for question in questions:
            selected_option = request.form.get(str(question['_id']))
            if selected_option and int(selected_option) == question['correct_option']:
                score += 1

        # Save quiz attempt
        mongo.db.attempts.insert_one({
            'user_id': session['user_id'],
            'score': score,
            'total': total,
            'time_taken': datetime.now(),
        })

        return render_template('result.html', score=score, total=total)

    return render_template('quiz.html', questions=questions)

@app.route('/add', methods=['GET', 'POST'])
def add_question():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({'_id': session['user_id']})
    if not user or not user.get('is_admin', False):
        return redirect(url_for('home'))  # Only admin can add questions

    if request.method == 'POST':
        question_text = request.form['question']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_option = int(request.form['correct_option'])

        # Insert the question into the database
        mongo.db.questions.insert_one({
            'question': question_text,
            'options': [option1, option2, option3, option4],
            'correct_option': correct_option
        })

        return redirect(url_for('admin_dashboard'))

    return render_template('add_question.html')

@app.route('/add-category', methods=['GET', 'POST'])
def add_category():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({'_id': session['user_id']})
    if not user or not user.get('is_admin', False):
        return redirect(url_for('home'))  # Only admin can add categories

    if request.method == 'POST':
        category_name = request.form['name']
        category_description = request.form['description']

        # Insert the category into the database
        mongo.db.categories.insert_one({
            'name': category_name,
            'description': category_description,
        })

        return redirect(url_for('admin_dashboard'))

    return render_template('add_category.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear the session to log out the user
    return redirect(url_for('login'))  # Redirect to the login page after logging out

if __name__ == '__main__':
    app.run(debug=True)
