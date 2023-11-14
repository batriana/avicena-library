from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField,BooleanField
from sqlalchemy.exc import IntegrityError
from wtforms.validators import InputRequired, Length
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.config['SECRET_KEY'] = 'swcpr0g'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mylibrary.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
csrf = CSRFProtect(app)

#define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)

class AdminUserRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[Length(min=6)])
    is_admin = BooleanField('Admin User')
    submit = SubmitField('Create User')

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[Length(min=6)])
    is_admin = BooleanField('Admin User')
    submit = SubmitField('Save Changes')

#define book model
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    publisher = db.Column(db.String(255))
    isbn = db.Column(db.String(13))
    version = db.Column(db.String(10))
    shelf = db.Column(db.String(50))
    available = db.Column(db.Boolean, default=True)

class EditBookForm(FlaskForm):
    title = StringField('Book Title', validators=[InputRequired()])
    author = StringField('Author', validators=[InputRequired()])
    publisher = StringField('Publisher')
    isbn = StringField('ISBN')
    version = StringField('Book Version')
    shelf = StringField('Shelf')
    submit = SubmitField('Edit Book')

# Create tables
with app.app_context():
    db.create_all()

    app.run(debug=True)

@app.route('/')
def home():
    form = LoginForm()  # Create an instance of the LoginForm
    return render_template('login.html', form=form)  # Pass the form to the template


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Log In')

# Create tables
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Create an admin user within the app context
    admin_user = User(username='admin', password='admin123', is_admin=True)

    try:
        db.session.add(admin_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()

#routes for admin and user signup/login
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    message = None 

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            message = 'Username already exists. Please choose a different one.'
        else:
            # If the username is unique, create a new user and add it to the database
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            message = 'Account created successfully'

    return render_template('signup.html', form=form, message=message)

#login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user:
            if user.password == password:
                login_user(user)
                
                if user.is_admin:
                    return redirect(url_for('admin_home'))
                else:
                    return redirect(url_for('user_home'))
            else:
                # Redirect to login page with an error parameter for incorrect password
                return redirect(url_for('login', login_error='incorrect_password'))
        else:
            # Redirect to login page with an error parameter for username not found
            return redirect(url_for('login', login_error='username_not_found'))
    elif request.method == 'POST':
        # Redirect to login page with an error parameter for missing fields
        return redirect(url_for('login', login_error='missing_fields'))

    return render_template('login.html', form=form)

#logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error('Server Error: %s', e)
    return 'Internal Server Error', 500

#create book
class AddBookForm(FlaskForm):
    title = StringField('Book Title', validators=[InputRequired()])
    author = StringField('Author', validators=[InputRequired()])
    publisher = StringField('Publisher')
    isbn = StringField('ISBN')
    version = StringField('Book Version')
    shelf = StringField('Shelf')
    submit = SubmitField('Add Book')

#CRUD books
@app.route('/admin_home', methods=['GET', 'POST'])
@login_required
def admin_home():

    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_home'))

    search_results = None
    form = AddBookForm()
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        books = Book.query.filter(
            (Book.title.like(f"%{search_query}%")) |
            (Book.author.like(f"%{search_query}%"))
        ).all()
        search_results = books

    books = Book.query.all()  #retrieve books from database
    users = User.query.all()  #retrieve users from db
    return render_template('admin/admin_home.html', books=books, users=users, search_results=search_results, form=form)

#add new book
@app.route('/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    form = AddBookForm()
    message = None
    added_book = False

    if request.method == 'POST' and form.validate_on_submit():
        title = form.title.data
        version = form.version.data

        #check if a book with the same ISBN already exists
        existing_book = Book.query.filter(
            (Book.title == title) & (Book.version == version)).first()
        if existing_book:
            return redirect(url_for('add_book', book_exists='true'))
        else:
            #create a new Book instance with the provided data
            new_book = Book(
                title=title,
                author=form.author.data,
                publisher=form.publisher.data,
                isbn=form.isbn.data,
                version=version,
                shelf=form.shelf.data
            )

            #add the new book to the database and commit the transaction
            db.session.add(new_book)
            db.session.commit()
            added_book = True

        if added_book:
            # Redirect with the added_book flag
            return redirect(url_for('add_book', added_book='true'))
        else:
            # Redirect with the message if the book already exists
            return redirect(url_for('add_book', message=message))

    return render_template('admin/add_book.html', form=form, added_book=added_book, message=message)

#deleting book
@app.route('/delete_book/<int:book_id>', methods=['POST'])
@login_required
def delete_book(book_id):
    # Delete the book with the given book_id
    book = Book.query.get(book_id)

    if book:
        db.session.delete(book)
        db.session.commit()
        return '<script>alert("Book deleted successfully"); window.location.replace("/admin_home");</script>'
    else:
        return '<script>alert("Book not found"); window.location.replace("/admin_home");</script>'

#book availability update
@app.route('/toggle_availability/<int:book_id>', methods=['GET', 'POST'])
@login_required
def toggle_availability(book_id):
    # Retrieve the book with the given book_id
    book = Book.query.get(book_id)

    if book:
        # Toggle the availability of the book
        book.available = not book.available
        db.session.commit()
        return redirect(url_for('admin_home'))
    else:
        flash('Book not found', 'danger')
        return redirect(url_for('admin_home'))

#view book details
@app.route('/view_book/<int:book_id>')
@login_required
def view_book(book_id):
    # Retrieve the book with the given book_id
    book = Book.query.get(book_id)
    if not book:
        flash('Book not found', 'danger')
        return redirect(url_for('admin_home'))
    return render_template('admin/view_book.html', book=book)

#edit book details
@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = Book.query.get(book_id)
    form = EditBookForm(obj=book)
    message = None
    edited_book = False
    version_exists = False

    if request.method == 'POST' and form.validate_on_submit():
        # Check if the ISBN already exists in the database
        existing_book = Book.query.filter(
            (Book.id != book.id) &
            (Book.title == form.title.data) &
            (Book.version == form.version.data)
        ).first()
        if existing_book:
            # Set the 'isbn_exists' flag to True
            return redirect(url_for('edit_book', book_id=book_id, version_exists=True))
            
        else:
            # Update book details with the data from the form
            book.title = form.title.data
            book.author = form.author.data
            book.publisher = form.publisher.data
            book.isbn = form.isbn.data
            book.version = form.version.data
            book.shelf = form.shelf.data

            # Commit the changes to the database
            db.session.commit()
            edited_book = True

        if edited_book:
            # Redirect with the edited_book flag
            return redirect(url_for('edit_book', book_id=book_id, edited_book=True))
        elif version_exists:
            # Redirect with the version_exists flag
            return redirect(url_for('edit_book', book_id=book_id, version_exists=True))

    return render_template('admin/edit_book.html', form=form, message=message, book=book)

#CRUD on user
#add new user
@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required  # Ensure that only logged-in admins can access this route
def create_user():
    form = AdminUserRegistrationForm()
    message = None
    added_user = False

    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        is_admin = form.is_admin.data

        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return redirect(url_for('create_user', user_exists='true'))
        else:
            #create a new user with the provided data
            new_user = User(username=username, password=password, is_admin=is_admin)

        #add user
        db.session.add(new_user)
        db.session.commit()
        #added_user = True

        # Redirect with the added_user flag
        return redirect(url_for('create_user', added_user='true'))

    return render_template('admin/add_user.html', form=form, added_user=added_user, message=message)

# Edit user details
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get(user_id)
    form = EditUserForm(obj=user)
    message = None
    edited_user = False

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_home'))

    if request.method == 'POST' and form.validate_on_submit():
        new_username = form.username.data

        #check if the new username already exists in the database
        existing_user = User.query.filter(User.id != user.id, User.username == new_username).first()
        if existing_user:
            return redirect(url_for('edit_user', user_id=user_id, edit_user_result='exists'))

        user.username = new_username
        user.is_admin = form.is_admin.data

        #update the password as well
        if form.password.data:
            user.password = form.password.data

        db.session.commit()
        edited_user = True

        if edited_user:
            # Redirect with the edited_user flag
            return redirect(url_for('edit_user', user_id=user_id, edited_user='true'))

    form.is_admin.data = user.is_admin

    return render_template('admin/edit_user.html', form=form, message=message)

#delete user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    else:
        flash('User not found', 'danger')

    return redirect(url_for('admin_home'))

#user account
# Create a route to display available books
@app.route('/user_home')
@login_required  # Ensure that only logged-in users can access this route
def user_home():
    # Retrieve available books from the database
    available_books = Book.query.filter_by(available=True).all()
    
    return render_template('user/user_home.html', books=available_books)

if __name__ == '__main__':
    app.run(debug=True)