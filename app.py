from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash  # Updated import
import bcrypt
from datetime import datetime
from bson.objectid import ObjectId 

app = Flask(__name__)

# Set up the secret key for sessions
app.secret_key = 'your_secret_key_here'

# MongoDB setup
app.config["MONGO_URI"] = "mongodb://localhost:27017/your_database"
mongo = PyMongo(app)

@app.route('/')
def home():
    # Ensure the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        # Convert the session user_id to an ObjectId to query MongoDB
        user_id = ObjectId(session['user_id'])
        
        # Fetch the user from the database
        user = mongo.db.users.find_one({'_id': user_id})
        
        # Handle the case where no user is found
        if not user:
            session.clear()  # Clear invalid session data
            return redirect(url_for('login'))

        # Redirect admin users to the admin dashboard
        if user.get('is_admin', False):
            return redirect(url_for('admin_dashboard'))

        # Redirect regular users to the home page (template not shown)
        return render_template('home.html', user=user)

    except Exception as e:
        # Log the error for debugging (optional: use a logging system here)
        print(f"Error in home route: {e}")
        session.clear()  # Clear session data to prevent further issues
        return redirect(url_for('login'))
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = mongo.db.users.find_one({'email': email})

        if user:
            # Check if password matches "ADMINadmin"
            if password == 'ADMINadmin':
                session['user_id'] = str(user['_id'])
                session['user_name'] = user['name']
                session['is_admin_temp'] = True  # Temporary admin access for the session
                return redirect(url_for('admin_dashboard_temp'))

            # Otherwise, check the hashed password
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                session['user_id'] = str(user['_id'])
                session['user_name'] = user['name']
                session['is_admin'] = user.get('is_admin', False)
                return redirect(url_for('home'))

        return "Invalid login credentials. Please try again."

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


@app.route('/admin/temp_dashboard')
def admin_dashboard_temp():
    if 'user_id' not in session or not session.get('is_admin_temp', False):
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({'_id': session['user_id']})
    return render_template('admin_temp_dashboard.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({'_id': session['user_id']})

    if request.method == 'POST':
        # Update the user's profile details
        name = request.form.get('name')
        email = request.form.get('email')

        if name:
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'name': name}})
        if email:
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'email': email}})
        
        return redirect(url_for('admin_dashboard_temp'))

    return render_template('edit_profile.html', user=user)
@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch all questions from the database
    questions = list(mongo.db.questions.find())

    # Get the current question index from the session, default to 0
    current_index = session.get('current_question_index', 0)

    # Initialize or update user answers in the session
    if 'answers' not in session:
        session['answers'] = [None] * len(questions)

    if request.method == 'POST':
        # Save the selected answer for the current question
        selected_option = request.form.get('answer')
        if selected_option is not None:
            session['answers'][current_index] = int(selected_option)

        # Check if the user clicked "Next" or "Previous"
        if 'next' in request.form:
            current_index += 1
        elif 'previous' in request.form:
            current_index -= 1
        elif 'submit' in request.form:
            # Calculate the score and save the results
            score = 0
            for i, question in enumerate(questions):
                if session['answers'][i] == question['correct_option']:
                    score += 1

            # Save quiz attempt in the database
            mongo.db.attempts.insert_one({
                'user_id': session['user_id'],
                'score': score,
                'total': len(questions),
                'time_taken': datetime.now(),
            })

            # Clear session data related to the quiz
            session.pop('current_question_index', None)
            session.pop('answers', None)

            return render_template('result.html', score=score, total=len(questions))

        # Update the current question index in the session
        session['current_question_index'] = current_index

    # Handle edge cases for navigation
    current_index = max(0, min(current_index, len(questions) - 1))

    # Render the current question
    current_question = questions[current_index]
    return render_template('quiz.html', question=current_question, current_index=current_index, total=len(questions))

@app.route('/quiz/results')
def quiz_results():
    if 'quiz_results' not in session:
        return redirect(url_for('quiz'))

    results = session['quiz_results']
    return render_template('quiz_results.html', **results)


@app.route('/add', methods=['GET', 'POST'])
def add_question():
    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if no session

    try:
        # Convert session user_id back to ObjectId
        user_id = ObjectId(session['user_id'])
    except Exception as e:
        print(f"Error converting user_id: {e}")
        return redirect(url_for('login'))

    # Retrieve the user from the database
    user = mongo.db.users.find_one({'_id': user_id})
    print(f"Logged in user: {user}")  # Debugging statement

    # Verify if the user exists and is an admin
    if not user or not user.get('is_admin', False):
        return redirect(url_for('home'))  # Redirect non-admin users

    # Fetch all categories from the database
    categories = list(mongo.db.categories.find())

    # If POST request, process the form submission
    if request.method == 'POST':
        category_id = request.form.get('category')
        question_text = request.form['question']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_option = int(request.form['correct_option'])

        # Validate the selected category
        if not category_id or not mongo.db.categories.find_one({'_id': ObjectId(category_id)}):
            flash('Invalid category selected. Please try again.', 'error')
            return redirect(url_for('add_question'))

        # Insert the question into the database
        mongo.db.questions.insert_one({
            'category_id': ObjectId(category_id),
            'question': question_text,
            'options': [option1, option2, option3, option4],
            'correct_option': correct_option
        })

        flash('Question added successfully!', 'success')
        return redirect(url_for('add_question'))  # Stay on the add question page

    # Render the add question form, passing categories to the template
    return render_template('add_question.html', categories=categories)

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

        return redirect(url_for('add_category'))

    return render_template('add_category.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear the session to log out the user
    return redirect(url_for('login'))  # Redirect to the login page after logging out

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)
