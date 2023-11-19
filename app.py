from flask import Flask, render_template, flash, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy import not_,update,or_
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String





app = Flask(__name__)
app.config['SECRET_KEY'] = '123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.jinja_env.filters['zip'] = zip

engine = create_engine('sqlite:///site.db')

conn = engine.connect()

print(conn)



# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'candidate', 'admin', 'company'
    skillset = db.Column(db.String(255),default=None)
    experience = db.Column(db.Integer,default=None)
    salary = db.Column(db.Float, default=None)
    password_hash = db.Column(db.String(128))  # Store the hashed password, not the plain text

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    required_skills = db.Column(db.String(255), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # applications = db.relationship('Application', backref='job', lazy=True)
    


class Application(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    candidate = db.relationship('User', foreign_keys=[candidate_id])
    job = db.relationship('Job', foreign_keys=[job_id])
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = StringField('Role')
    skillset = StringField('Skillset')
    experience = StringField('Experience')
    salary = StringField('Salary')
    secret=StringField('Secret')
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CreateJobForm(FlaskForm):
    title = StringField('Job Title', validators=[DataRequired()])
    description = StringField('Job Description', validators=[DataRequired()])
    required_skills = StringField('Required Skills', validators=[DataRequired()])
    submit = SubmitField('Create Job')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role='Candidate',
            skillset=form.skillset.data,
            experience=form.experience.data,
            salary=form.salary.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        print(user)

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/admin_register', methods=['GET', 'POST'])
def Admin_register():
    s='Rohan'
    form = RegistrationForm()
    if form.validate_on_submit() and (form.secret.data==s):
        user = User(
            username=form.username.data,
            email=form.email.data,
            role="Admin",
            
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        print(user)

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/company_register', methods=['GET', 'POST'])
def company_register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role="Company",
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        print(user)

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful.', 'success')
           
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'Company':
        return redirect(url_for('company_dashboard'))
    else:
        return redirect(url_for('candidate_dashboard'))


@app.route('/company/dashboard')
@login_required
def company_dashboard():
    # Add logic for company dashboard

    return render_template('company_dashboard.html')

@app.route('/candidate/dashboard', methods=['GET', 'POST'])
@login_required
def candidate_dashboard():
    if request.method == 'POST':
        new_skill = request.form.get('new_skill')
        if new_skill:
            # Update the user's skillset in the database
            current_user.skillset += ',' + new_skill
            db.session.commit()
            flash(f'Skill "{new_skill}" added successfully.', 'success')

        # Handling job application
        job_id_to_apply = request.form.get('job_id_to_apply')
        if job_id_to_apply:
            # Check if the candidate has already applied to the job
            if not Application.query.filter_by(candidate_id=current_user.id, job_id=job_id_to_apply).first():
                job_to_apply = Job.query.get(job_id_to_apply)
                if job_to_apply:
                    application = Application(candidate_id=current_user.id, job_id=job_id_to_apply)
                    db.session.add(application)
                    db.session.commit()
                    flash(f'Applied successfully for the job "{job_to_apply.title}".', 'success')
                else:
                    flash('Job not found.', 'error')
            else:
                flash('You have already applied to this job.', 'warning')

    user_skillset = current_user.skillset.split(",")

    # Get job IDs for jobs that match the candidate's skillset
    matching_jobs_ids = [job.id for job in Job.query.filter(or_(*(Job.required_skills.contains(skill) for skill in user_skillset))).all()]

    # Get available jobs that match the candidate's skillset
    available_jobs = Job.query.filter(Job.id.in_(matching_jobs_ids)).all()

    applied_jobs_ids = [application.job_id for application in Application.query.filter(Application.candidate_id == current_user.id).all()]
    applied_jobs = Job.query.filter(Job.id.in_(applied_jobs_ids)).all()
    status = [application.status for application in Application.query.filter(Application.candidate_id == current_user.id).all()]

    return render_template('candidate_dashboard.html', available_jobs=available_jobs, applied_jobs=applied_jobs, status=status, skillset=user_skillset)

@app.route('/create_job', methods=['GET', 'POST'])
@login_required
def create_job():
    form = CreateJobForm()
    if form.validate_on_submit():
        job = Job(
            title=form.title.data,
            description=form.description.data,
            required_skills=form.required_skills.data,
            company_id=current_user.id
        )
        db.session.add(job)
        db.session.commit()
        flash('Job created successfully.', 'success')
        return redirect(url_for('company_dashboard'))

    return render_template('create_job.html', form=form)


@app.route('/apply_job/<int:job_id>')
@login_required
def apply_job(job_id):
    job = Job.query.get(job_id)
    
    if not job:
        flash('Job not found.', 'danger')
    else:
        application = Application(candidate=current_user, job=job)
        db.session.add(application)
        db.session.commit()
        flash('Application submitted successfully.', 'success')

    return redirect(url_for('candidate_dashboard'))


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        flash('Permission denied. You are not authorized to view this page.', 'danger')
        return redirect(url_for('index'))

    return render_template('admin_dashboard.html')

@app.route('/admin/view_candidates')
@login_required
def view_candidates():
    if current_user.role != 'Admin':
        flash('Permission denied. You are not authorized to view this page.', 'danger')
        return redirect(url_for('index'))

    sort_attribute = request.args.get('sort', 'username')
    order = request.args.get('order', 'asc')

    if sort_attribute not in ['username', 'experience', 'salary', 'skillset']:
        sort_attribute = 'username'

    candidates = User.query.filter(User.role == 'Candidate').order_by(
        getattr(User, sort_attribute).asc() if order == 'asc' else getattr(User, sort_attribute).desc()
    ).all()

    return render_template('admin_view_candidates.html', candidates=candidates, sort_attribute=sort_attribute, order=order)



@app.route('/admin/view_applications', methods=['GET', 'POST'])
@login_required
def view_applications():
    if current_user.role != 'Admin':
        flash('Permission denied. You are not authorized to view this page.', 'danger')
        return redirect(url_for('index'))
    if request.method=='POST':
        app_row=Application.query.filter(Application.id==request.form.get('application_id')).first()
        app_row.status=request.form.get('decision')
        db.session.commit()

    
    company=User.query.filter(User.role=='Company')
    company_dict={}
    for com in company:
        company_dict[com.id]=com.username
    candidates = User.query.filter(User.role=='Candidate')
    candidate_dict={}
    for candidate in candidates:
        candidate_dict[candidate.id]={'username':candidate.username,
        'skills':candidate.skillset,
        'salary':candidate.salary,
        'exp':candidate.experience}
    appl = db.session.query(Application,Job).join(Job,Job.id == Application.job)
    applications=[]
    for d in appl:
        applications.append({
        'app_id':d[0].id,
        'job_id':d[0].job_id,
        'company':company_dict[d[1].company_id],
        'candidate':candidate_dict[d[0].candidate_id]['username'],
        'c_skills':candidate_dict[d[0].candidate_id]['skills'], 'c_salary':candidate_dict[d[0].candidate_id]['salary'],
        'c_experience':candidate_dict[d[0].candidate_id]['exp'],
        'candidate_id':d[0].candidate_id,
        'skills_req':d[1].required_skills,
        'company_id':d[1].company_id,
        'job_title':d[1].title,
        'job_des':d[1].description,
        'status':d[0].status})
    print(applications)
    return render_template('admin_view_applications.html', applications=applications)


@app.route('/admin/job_company_statistics')
@login_required
def job_applications_graph():
    if current_user.role != 'Admin':
        flash('Permission denied. You are not authorized to view this page.', 'danger')
        return redirect(url_for('index'))

    # Adjust the time period as needed
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)  # Assuming a 30-day period

    applications = Application.query.join(Job).add_columns(
        Application.id,
        Job.title.label('job_title'),
        Job.company_id.label('company_id'),
        Application.created_at).filter(
        Application.created_at.between(start_date, end_date)
    ).all()

    # Create a DataFrame from the query results
    df = pd.DataFrame(applications, columns=['application_id', 'job_title', 'company_id', 'created_at',' '])
    
    print(applications)

    # Count the number of applications for each job title
    job_counts = df['job_title'].value_counts()

    # Count the number of applications for each company
    company_counts = df['company_id'].value_counts()

    # Plotting the data
    plt.figure(figsize=(12, 6))

    # Plotting the job counts
    plt.subplot(1, 2, 1)
    job_counts.plot(kind='bar', color='skyblue')
    plt.title('Companies Most Applied To')
    plt.xlabel('Company')
    plt.ylabel('Number of Applications')
    plt.xticks(rotation=45)

    # Plotting the company counts
    plt.subplot(1, 2, 2)
    company_counts.plot(kind='bar', color='salmon')
    plt.title('Jobs Most Applied To')
    plt.xlabel('Job Type')
    plt.ylabel('Number of Applications')
    plt.xticks(rotation=45)

    plt.tight_layout()

    # Save the plot to a BytesIO object
    img = BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    plt.close()

    return render_template('plot.html', plot_url=plot_url)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
