from flask import *
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime
import os
import uuid
import random
from flask_wtf.csrf import generate_csrf, validate_csrf
import secrets


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///main.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key ='a1cc8c3c1e2ee7b995d34b88712889d8'
db = SQLAlchemy(app)

starting_subjects = [
   "Introduction to Psychology",
   "Calculus I",
   "Calculus II", 
   "General Chemistry I",
   "General Chemistry II",
   "Organic Chemistry I",
   "General Biology I",
   "General Biology II",
   "Introduction to Computer Science",
   "Data Structures and Algorithms",
   "Microeconomics",
   "Macroeconomics",
   "College Composition I",
   "College Composition II",
   "American Literature",
   "World History I",
   "American History",
   "Introduction to Philosophy",
   "Ethics",
   "Statistics",
   "Linear Algebra",
   "Physics I",
   "Physics II",
   "Introduction to Sociology",
   "Political Science",
   "Spanish I",
   "Spanish II",
   "Art History",
   "Public Speaking",
   "Business Management"
]

starting_grades = [
   "A", 
   "A-",
   "B+",
   "B",
   "B-", 
   "C+",
   "C",
   "C-",
   "D+",
   "D",
   "D-",
   "F"
]

# Models
class Class(db.Model):
    __tablename__ = 'classes'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.String(36), db.ForeignKey('teachers.id'), nullable=True)
    
    teacher = db.relationship('Teacher', back_populates='classes')
    enrollments = db.relationship('Enrollment', back_populates='class_obj')

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    student_id = db.Column(db.String(36), db.ForeignKey('students.id'), nullable=False)
    class_id = db.Column(db.String(36), db.ForeignKey('classes.id'), nullable=False)
    grade = db.Column(db.String(5), nullable=True)

    feedback_rating = db.Column(db.Integer, nullable=True)
    feedback_comment = db.Column(db.Text, nullable=True)    
    feedback_submitted_at = db.Column(db.DateTime, nullable=True)
   
    student = db.relationship('Student', back_populates='enrollments')
    class_obj = db.relationship('Class', back_populates='enrollments')

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    
    __mapper_args__ = {
        'polymorphic_identity': 'user',
        'polymorphic_on': user_type
    }

class Student(User):
    __tablename__ = 'students'
    id = db.Column(db.String(36), db.ForeignKey('users.id'), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    enrollments = db.relationship('Enrollment', back_populates='student')
    
    __mapper_args__ = {'polymorphic_identity': 'student'}

class Teacher(User):
    __tablename__ = 'teachers'
    id = db.Column(db.String(36), db.ForeignKey('users.id'), primary_key=True, default=lambda: str(uuid.uuid4()))
    subject = db.Column(db.String(50), nullable=True)
    
    classes = db.relationship('Class', back_populates='teacher')
    
    __mapper_args__ = {'polymorphic_identity': 'teacher'}


with app.app_context():
    db.create_all() 

    if not Teacher.query.filter_by(username="msmith").first():
        t1 = Teacher(
            id="fc23dcd0-52aa-4f8e-bd65-71152de04d52",
            name="Mr. Smith",
            username="msmith",
            password="66f6d507eb5025a06f66d7b9e67e031c",
            subject="Math"
        )
        db.session.add(t1)
        db.session.commit()

@app.route('/')
def main():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    else:
        return redirect(url_for('dashboard', user_id=session['user_id']))

@app.route('/dashboard/<user_id>', methods=['GET'])
def dashboard(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    session_user_id = session['user_id']
    user_type = session['user_type']

    if user_type == 'teacher' and session['user_id'] == user_id:
        return redirect(url_for('grade_change'))
    
    # Get the student whose dashboard we want to view
    student = Student.query.get_or_404(user_id)
    
    if user_type == 'student' and session['user_id'] != user_id:
        flash('You can only view your own dashboard')
        return redirect(url_for('dashboard', user_id=session['user_id']))

    
    student_data = {
        'name': student.name,
        'username': student.username,
        'user_id': student.id,
        'enrollments': []
    }


    # Get actual enrollments with feedback data
    for enrollment in student.enrollments:
        student_data['enrollments'].append({
            'enrollment_id': enrollment.id,
            'class_id': enrollment.class_obj.id,
            'class_name': enrollment.class_obj.name,
            'grade': enrollment.grade or 'No grade yet',
            'teacher': enrollment.class_obj.teacher.name if enrollment.class_obj.teacher else 'No teacher assigned',
            'feedback_rating': enrollment.feedback_rating,
            'feedback_comment': enrollment.feedback_comment
        })
    
    response = make_response(render_template('dashboard.html', student=student_data))
    response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self' data:; style-src 'self' 'unsafe-inline'; img-src *; font-src *; connect-src 'self'; object-src 'none'; media-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'self'; form-action 'self';"
    return response

@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    student = Student.query.get_or_404(user_id)
    
    for enrollment in student.enrollments:
        rating_key = f"rating_{enrollment.id}"
        comment_key = f"comment_{enrollment.id}"
        
        rating = request.form.get(rating_key)
        comment = request.form.get(comment_key)
        
        # Update rating if provided
        if rating and rating.isdigit():
            rating_value = int(rating)
            if 1 <= rating_value <= 5:
                enrollment.feedback_rating = rating_value
                enrollment.feedback_submitted_at = datetime.now()
        
        # Update comment if provided
        if comment and comment.strip():
            enrollment.feedback_comment = comment.strip()
            if not enrollment.feedback_submitted_at:
                enrollment.feedback_submitted_at = datetime.now()
    
    db.session.commit()
    flash('Feedback submitted successfully!')
    return redirect(url_for('dashboard', user_id=session['user_id']))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method=="POST":
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')

        if not username:
            flash('Username is required')
            return redirect(url_for('register'))
        
        if not password:
            flash('Password is required')
            return redirect(url_for('register'))
        
        if len(password) < 12:
            flash('Password must be at least 12 characters long')
            return redirect(url_for('register'))
        else:  
            try:
                s1 = Student(name=name, username=username, password=password)
                db.session.add(s1)
                db.session.commit()

                chosen_subjects = random.sample(starting_subjects, 5)

                for subject in chosen_subjects:
                    cls = Class.query.filter_by(name=subject).first()
                    if not cls:
                        cls = Class(name=subject)
                        db.session.add(cls)
                        db.session.commit()

                    grade = random.choice(starting_grades)
                    enrollment = Enrollment(student=s1, class_obj=cls, grade=grade)
                    db.session.add(enrollment)

                db.session.commit()

                return redirect(url_for('login'))

            except IntegrityError:
                db.session.rollback()
                flash('Please select another username.')
                return redirect(url_for('register'))
            except:
                return redirect(url_for('register'))
                
    elif request.method=="GET":
        return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username, password=password).first()
        
        if user:
            # Store user info in session
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_type'] = user.user_type
            return redirect(url_for('dashboard', user_id=user.id))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/honor-roll-certificate', methods=['GET'])
def honor_roll():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user_type = session['user_type']

    if user_type == 'student':
        student = Student.query.get_or_404(user_id)
        
        student_letter_grades = [enrollment.grade for enrollment in student.enrollments]
        if all(grade=="A" for grade in student_letter_grades):
            return render_template_string("csawctf{y0u_m@de_the_h@cking_h0n0r_r0ll}")

        return render_template_string(f"<html>{student_letter_grades}</html>")
    else:
        return redirect(url_for('dashboard', user_id=session['user_id']))

@app.route('/grade-change', methods=['GET', 'POST'])
def grade_change():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session['user_type'] != 'teacher':
        flash('Access denied: Teachers only')
        return redirect(url_for('dashboard', user_id=session['user_id']))
    
    if request.method == 'POST':
        student_id = request.form.get('student_id')  
        class_id = request.form.get('class_id')
        new_grade = request.form.get('grade')
        csrf_token = request.form.get('csrf_token')

        try:
            validate_csrf(request.form.get('csrf_token'))
        except:
            return "CSRF token validation failed", 400
        
        if student_id and class_id and new_grade:
            try:
                # Find student by ID instead of username
                student = Student.query.get(student_id)
                if not student:
                    flash('Student not found')
                    return redirect(url_for('grade_change'))
                
                # Find enrollment
                enrollment = Enrollment.query.filter_by(
                    student_id=student.id, 
                    class_id=class_id
                ).first()
                
                if enrollment:
                    enrollment.grade = new_grade
                    db.session.commit()
                    flash(f'Grade updated for {student.name} (ID: {student_id})')
                else:
                    flash('Enrollment not found')
                    
            except Exception as e:
                flash('Error updating grade')
        return redirect(url_for('grade_change'))
    
    csrf_token = generate_csrf()
    response = make_response(render_template('grade-change.html', csrf_token=csrf_token))
    response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self' data:; style-src 'self' 'unsafe-inline'; img-src *; font-src *; connect-src 'self'; object-src 'none'; media-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'self'; form-action 'self';"
    return response


if __name__ == '__main__':
    app.run(debug=True, port=4747)