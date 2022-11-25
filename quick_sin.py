from flask import Flask, redirect, jsonify, current_app, url_for, render_template, request,flash,g,session, Response,send_file, make_response,send_from_directory
import logging
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField,IntegerField,RadioField
from wtforms.validators import InputRequired, Email, Length,NumberRange, ValidationError
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from sqlalchemy import delete,insert, update
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
from flask_login import  logout_user, LoginManager,current_user, UserMixin, login_required, login_user
import sentry_sdk
import os
import pymysql
import pymysql.cursors
from random import randint
from datetime import datetime
from pytz import timezone
#from scipy.io.wavfile import write
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
from datetime import date,datetime, timedelta
import time
from dotenv import load_dotenv
import smtplib
#import io
#from io import StringIO,BytesIO
#import simpleaudio as sa
#import soundfile as sf
#import pydub
#import sounddevice as sd
#from flask_mail import Mail, Message
#from flask_login import LoginManager, UserMixin, login_user,login_required,logout_user, current_user
import pandas as pd
import csv
import requests
from requests import post
#import redcap
#from redcap import Project, RedcapError
#import subprocess
#from subprocess import PIPE, run
from flask.sessions import SecureCookieSessionInterface
import dropbox_upload
import mysql.connector

app = Flask(__name__)
load_dotenv()

#libjack-jackd2-dev

dbuser=os.getenv('DBUSER')
dbpass=os.getenv('DBPASS')
dbhost=os.getenv('DBHOST')
dbname=os.getenv('DBNAME')
sentry_pw=os.getenv('SENTRY')

# Connect to the database
conn = f"mysql+pymysql://{dbuser}:{dbpass}@{dbhost}/{dbname}"


app.secret_key=os.urandom(12)
#mail = Mail(app)
#s = URLSafeTimedSerializer(app.secret_key)
bootstrap = Bootstrap(app)
sentry_sdk.init(
	sentry_pw,

	# Set traces_sample_rate to 1.0 to capture 100%
	# of transactions for performance monitoring.
	# We recommend adjusting this value in production.
	traces_sample_rate=1.0
)

app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.config['SQLALCHEMY_POOL_RECYCLE']=299
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE']='sqlalchemy'
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.permanent_session_lifetime = timedelta(minutes=15)  #How long you want to store session data? Put here
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db=SQLAlchemy(app)
app.config['SESSION_SQLALCHEMY']=db
sesh=Session(app)
session_cookie = SecureCookieSessionInterface().get_signing_serializer(app)


@app.after_request
def cookies(response):
    same_cookie = session_cookie.dumps(dict(session))
    response.headers.add("Set-Cookie", f"my_cookie={same_cookie}; Secure; httponly=True; SameSite='Lax';")
    return response


######LOGIN STUFF#########################
class User(UserMixin,db.Model):
	id=db.Column(db.Integer,primary_key=True)
	email = db.Column(db.String(500), unique=True)
	password = db.Column(db.String(500))
	created_on = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	#name = db.Column(db.String(50), unique=True)
	#age=db.Column(db.Integer)
	#sex=db.Column(db.String(30))
	#ethnicity=db.Column(db.String(50))
	completed=db.Column(db.String(500),default='no')
	started_at=db.Column(db.DateTime)
	completed_on=db.Column(db.DateTime)
	security_secret1=db.Column(db.String(500))
	security_secret2=db.Column(db.String(500))
	role=db.Column(db.String(500),default='participant')

	#Other ideas?:
	#Time it took to complete, Save pdf of certificate in db, DONT save name
'''
def validate_email(form, field):
	if field.data[-3:-1]+field.data[-1] != 'edu':
		raise ValidationError("'Email Address Must End with 'edu'")
'''
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))
class LoginForm(FlaskForm):
	email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
	password = PasswordField('Password', validators=[InputRequired()])
	remember = BooleanField('I agree to these Terms and Conditions.', validators=[InputRequired()])
class RegisterForm(FlaskForm):
	#name = StringField('Full Name', validators=[InputRequired(), Length(min=4, max=15)])
	email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
	password = PasswordField('Password', validators=[InputRequired()])
	#age=IntegerField('Age',validators=[InputRequired(),NumberRange(min=18,max=80,message='Participants should be between the ages of 18 and 80')])
	#sex = RadioField('Biological Sex', choices=[('Male','Male'), ('Female','Female'), ('Other/Prefer Not to Disclose','Other/Prefer Not to Disclose')],validators=[InputRequired()])
	#ethnicity = RadioField('Ethnicity', choices=[('American Indian or Alaska Native','American Indian or Alaska Native'), ('Asian','Asian'), ('Black or African American','Black or African American'),('Hispanic or Latino','Hispanic or Latino'),('Native Hawaiian or Other Pacific Islander','Native Hawaiian or Other Pacific Islander'),('White','White')],validators=[InputRequired()])
	#https://grants.nih.gov/grants/guide/notice-files/not-od-15-089.html
	security_secret1=StringField('What city were you born in?',validators=[InputRequired()])
	security_secret2=StringField('What is your favorite color?',validators=[InputRequired()])

@app.route('/login', methods=['GET', 'POST'])
@app.route("/",methods=["GET","POST"])
@app.route("/home",methods=["GET","POST"])
def login():
	form = LoginForm()
	message=""
	if current_user.is_authenticated==True:
		return redirect(url_for('logout'))
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user:
			if check_password_hash(user.password, form.password.data):
				# check if a record exists for them in the StripeCustomer table
				login_user(user, remember=form.remember)
				now_user=User.query.filter_by(email=current_user.email).first()
				if now_user.role=="participant":
					return redirect(url_for('user_menu'))
				if now_user.role=="admin":
					return redirect(url_for('verify_admin'))
			return render_template("login.html",message="Invalid email or password.",form=form)
		return render_template("login.html",message="Please create a valid account.",form=form)
	return render_template('login.html', message=message, form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = RegisterForm()
	if form.validate_on_submit():
		hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256',salt_length=16)
		email=form.email.data
		ss1=generate_password_hash(form.security_secret1.data,method='pbkdf2:sha256',salt_length=16)
		#age=form.age.data
		#sex=form.sex.data
		#ethnicity=form.ethnicity.data
		ss2=generate_password_hash(form.security_secret2.data,method='pbkdf2:sha256',salt_length=16)
		database=User.query.filter_by(email=email).first()
		if database!=None:
			return render_template('signup.html',form=form,message='Email has been taken. Please try a different email or login.')
		else:
			new_user = User(email=email, password=hashed_password,security_secret1=ss1,security_secret2=ss2)
			db.session.add(new_user)
			db.session.commit()
			email=new_user.email
			return redirect(url_for('login'))

	return render_template('signup.html', form=form)


'''
Routes: LOGIN/Home (or Signup) -->USER HOME-->INSTRUCTIONS-->CALIBRATE-->TRACK1-->TRACK2-->TRACK3-->TRACK4--->TRACK5-->TRACK6-->USER HOME
+ADMIN PAGE
'''
'''
@app.route('/consent', methods=['GET', 'POST'])
@login_required
def consent():
	return render_template('consent.html')
'''

#######################################################################################################################


@app.route('/user_menu', methods=['GET', 'POST'])
@login_required
def user_menu():
	if current_user.is_authenticated==False:
		return redirect(url_for('login'))
	if current_user.role=="admin":
		return redirect(url_for('verify_admin'))
	return render_template('user_menu.html')

@app.route('/instructions', methods=['GET', 'POST'])
@login_required
def instructions():
	return render_template('instructions.html')

@app.route('/calibration', methods=['GET', 'POST'])
@login_required
def calibration():
	return render_template('calibration.html')

@app.route('/calibration2', methods=['GET', 'POST'])
@login_required
def calibration2():
	message2=""
	if request.method=="POST": ###CORRECT ANSWER: LRRL
		answer = request.form['options']
		if answer =="Left, Right, Right, Left":
			message2="Done! Your speakers are working correctly."
			return render_template('calibration2.html',message2=message2)
		else:
			message2="It seems your headphones aren't working properly.\nPlease try switching sides of the headphones (if you can discriminate sides) or try using different headphones."
			return render_template('calibration2.html',message2=message2)
	return render_template('calibration2.html', message2=message2)

@app.route('/calibration3', methods=['GET', 'POST'])
@login_required
def calibration3():
	return render_template('calibration3.html')

@app.route('/trial_track', methods=['GET', 'POST'])
@login_required
def trial_track():
    pid=current_user.id
    if current_user.completed=="yes":
        return redirect(url_for('user_menu'))
    if request.method == "POST":
        f = request.files['audio_data']
        with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_trial.wav', 'wb') as audio:
            f.save(audio)
        dropbox_upload.main()
        if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_trial.wav"):
            os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_trial.wav")
        print('successfully uploaded, deleted, now redirecting')
        return redirect(url_for('first_track'))
    return render_template('trial_track.html')

@app.route('/trial_set', methods=['GET','POST'])
@login_required
def trial_set():
	pid=current_user.id
	if current_user.completed=="yes":
		return redirect(url_for('user_menu'))
	if request.method == "POST":
		f = request.files['audio_data']
		with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_trial.wav', 'wb') as audio:
			f.save(audio)
		dropbox_upload.main()
		if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_trial.wav"):
			os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_trial.wav")
		print('successfully uploaded, deleted, now redirecting')
		return redirect(url_for('first_track'))
	return render_template('trial_track.html')

@app.route('/first_track', methods=['GET', 'POST'])
@login_required
def first_track():
    pid=current_user.id
    if current_user.completed=="yes":
        return redirect(url_for('user_menu'))
    if request.method == "POST":
        f = request.files['audio_data']
        print("this works!")
        with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_first.wav', 'wb') as audio:
            f.save(audio)
        print("this works!")
        dropbox_upload.main()
        print("done, now deleting")
        if os.path.exists(f'/home/HearingSINTest/mysite/Downloads/{pid}_first.wav'):
            os.remove(f'/home/HearingSINTest/mysite/Downloads/{pid}_first.wav')
        print('successfully deleted, now redirecting')
        return redirect(url_for('second_track'))
    return render_template('first_track.html')

@app.route('/first_set', methods=['GET','POST'])
@login_required
def first_set():
	pid=current_user.id
	if current_user.completed=="yes":
		return redirect(url_for('user_menu'))
	if request.method == "POST":
		f = request.files['audio_data']
		print("this works!")
		with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_first.wav', 'wb') as audio:
			f.save(audio)
		print("this works!")
		dropbox_upload.main()
		print("done, now deleting")
		if os.path.exists(f'/home/HearingSINTest/mysite/Downloads/{pid}_first.wav'):
			os.remove(f'/home/HearingSINTest/mysite/Downloads/{pid}_first.wav')
		print('successfully deleted, now redirecting')
		return redirect(url_for('second_track'))
	return render_template('first_track.html')

@app.route('/second_track', methods=['GET', 'POST'])
@login_required
def second_track():
    pid=current_user.id
    if current_user.completed=="yes":
        return redirect(url_for('user_menu'))
    if request.method == "POST":
        f = request.files['audio_data']
        with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_second.wav', 'wb') as audio:
            f.save(audio)
        dropbox_upload.main()
        if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_second.wav"):
            os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_second.wav")
        print('successfully uploaded, deleted, now redirecting')
        return redirect(url_for('third_track'))
    return render_template('second_track.html')

@app.route('/second_set', methods=['GET','POST'])
@login_required
def second_set():
	pid=current_user.id
	if current_user.completed=="yes":
		return redirect(url_for('user_menu'))
	if request.method == "POST":
		f = request.files['audio_data']
		with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_second.wav', 'wb') as audio:
			f.save(audio)
		dropbox_upload.main()
		if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_second.wav"):
			os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_second.wav")
		print('successfully uploaded, deleted, now redirecting')
		return redirect(url_for('third_track'))
	return render_template('second_track.html')

@app.route('/third_track', methods=['GET', 'POST'])
@login_required
def third_track():
    pid=current_user.id
    if current_user.completed=="yes":
        return redirect(url_for('user_menu'))
    if request.method == "POST":
        f = request.files['audio_data']
        with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_third.wav', 'wb') as audio:
            f.save(audio)
        dropbox_upload.main()
        if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_third.wav"):
            os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_third.wav")
        print('successfully uploaded, deleted, now redirecting')
        return redirect(url_for('fourth_track'))
    return render_template('third_track.html')

@app.route('/third_set', methods=['GET','POST'])
@login_required
def third_set():
	pid=current_user.id
	if current_user.completed=="yes":
		return redirect(url_for('user_menu'))
	if request.method == "POST":
		f = request.files['audio_data']
		with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_third.wav', 'wb') as audio:
			f.save(audio)
		dropbox_upload.main()
		if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_third.wav"):
			os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_third.wav")
		print('successfully uploaded, deleted, now redirecting')
		return redirect(url_for('fourth_track'))
	return render_template('third_track.html')

@app.route('/fourth_track', methods=['GET', 'POST'])
@login_required
def fourth_track():
    pid=current_user.id
    if current_user.completed=="yes":
        return redirect(url_for('user_menu'))
    if request.method == "POST":
        f = request.files['audio_data']
        with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav', 'wb') as audio:
            f.save(audio)
            dropbox_upload.main()
        if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav"):
            os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav")
        print('successfully uploaded, deleted, now redirecting')
        return redirect(url_for('fifth_track'))
    return render_template('fourth_track.html')

@app.route('/fourth_set', methods=['GET','POST'])
@login_required
def fourth_set():
	pid=current_user.id
	if current_user.completed=="yes":
		return redirect(url_for('user_menu'))
	if request.method == "POST":
		f = request.files['audio_data']
		with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav', 'wb') as audio:
			f.save(audio)
		dropbox_upload.main()
		if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav"):
			os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav")
		print('successfully uploaded, deleted, now redirecting')
		return redirect(url_for('fifth_track'))
	return render_template('fourth_track.html')

@app.route('/fifth_track', methods=['GET', 'POST'])
@login_required
def fifth_track():
    pid=current_user.id
    if current_user.completed=="yes":
        return redirect(url_for('user_menu'))
    if request.method == "POST":
        f = request.files['audio_data']
        with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav', 'wb') as audio:
            f.save(audio)
        dropbox_upload.main()
        if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav"):
            os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_fourth.wav")
        print('successfully uploaded, deleted, now redirecting')
        return redirect(url_for('fifth_track'))
    return render_template('fifth_track.html')

@app.route('/fifth_set', methods=['GET','POST'])
@login_required
def fifth_set():
	pid=current_user.id
	if current_user.completed=="yes":
		return redirect(url_for('user_menu'))
	if request.method == "POST":
		f = request.files['audio_data']
		with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_fifth.wav', 'wb') as audio:
			f.save(audio)
		dropbox_upload.main()
		if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_fifth.wav"):
			os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_fifth.wav")
		print('successfully uploaded, deleted, now redirecting')
		return redirect(url_for('fifth_track'))
	return render_template('fifth_track.html')

@app.route('/sixth_track', methods=['GET', 'POST'])
@login_required
def sixth_track():
    pid=current_user.id
    if current_user.completed=="yes":
        return redirect(url_for('user_menu'))
    if request.method=="POST":
	    f = request.files['audio_data']
	    with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_sixth.wav', 'wb') as audio:
	        f.save(audio)
	    dropbox_upload.main()
	    if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_sixth.wav"):
	        os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_sixth.wav")
	    print('uploaded and deleted successfully')
	    email=current_user.email
	    user=User.query.filter_by(email=email).first()
	    user.completed="yes"
	    now_utc = datetime.now(timezone('UTC'))
	    user.completed_on=now_utc
	    db.session.commit()
	    return redirect(url_for('proof_of_completion'))
    return render_template('sixth_track.html')

@app.route('/sixth_set', methods=['GET','POST'])
@login_required
def sixth_set():
	pid=current_user.id
	if current_user.completed=="yes":
		return redirect(url_for('user_menu'))
	if request.method == "POST":
		f = request.files['audio_data']
		with open(f'/home/HearingSINTest/mysite/Downloads/{pid}_sixth.wav', 'wb') as audio:
			f.save(audio)
		dropbox_upload.main()
		if os.path.exists(f"/home/HearingSINTest/mysite/Downloads/{pid}_sixth.wav"):
			os.remove(f"/home/HearingSINTest/mysite/Downloads/{pid}_sixth.wav")
		print('uploaded and deleted successfully')
		email=current_user.email
		user=User.query.filter_by(email=email).first()
		user.completed="yes"
		# Current time in UTC
		now_utc = datetime.now(timezone('UTC'))
		user.completed_on=now_utc
		db.session.commit()
		return redirect(url_for('proof_of_completion'))
	return render_template('sixth_track.html')

####AboutUs#####
@app.route("/aboutus")
def aboutus():
	return render_template('aboutus.html')

####PROOF OF COMPLETION#####
@app.route("/proof_of_completion")
@login_required
def proof_of_completion():
	email=current_user.email
	user=User.query.filter_by(email=email).first()
	if user.completed=="no":
		return redirect(url_for('user_menu'))
	elif user.role=="admin":
		return redirect(url_for('verify_admin'))
	else:
		return render_template('proof_of_completion.html')

####Forget PW#####
@app.route("/forget_password",methods=['POST','GET'])
def forget_password():
	message=''
	if request.method=='POST':
		email=request.form['email']
		secret1=request.form['secret1']
		secret2=request.form['secret2']
		new_password=request.form['password']
		user=User.query.filter_by(email=email).first()
		if user==None:
			message='Please enter a valid email that is registered with HearingSIN-Test.'
			return render_template('forget_password.html',message=message)
		elif check_password_hash(user.security_secret1, secret1)==False or check_password_hash(user.security_secret2,secret2)==False:
			message="Please doublecheck your credentials again."
			return render_template('forget_password.html',message=message)
		else:
			hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256',salt_length=16)
			user.password=hashed_password
			db.session.commit()
			return render_template("forget_password.html",message="Password changed!")
	return render_template('forget_password.html',message=message)


###LOG OUT
@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))

###LOG OUT
@app.route('/instructions2')
@login_required
def instructions2():
	return render_template('instructions2.html')

###SEND VERIFICATION
@app.route('/verify_admin',methods=['GET','POST'])
@login_required
def verify_admin():
	now_user=User.query.filter_by(email=current_user.email).first()
	if now_user.role!='admin':
		return redirect(url_for('user_menu'))
	if request.method=='POST':
		#code=randint(100000,999999)
		#session['code']=code
		#text=f'Subject: Verification Code\n\nThis is a no-reply email from HearingSIN-Test Online\n\nYour verification code is {code}'
		#server=smtplib.SMTP("smtp.gmail.com",587)
		#server.starttls()
		#server.login("quicksin.online@gmail.com",f'{password}')
		#server.sendmail("quicksin.online@gmail.com",f"{now_user.email}",text)
		pw= request.form['pw']
		password=os.getenv("PASSWORD")
		if pw==password:
		    print("Admin verified. Welcome, Admin!")
		    return redirect(url_for('admin'))
		print("Go away! You're not the admin!")
		return redirect(url_for('logout'))
	return render_template('verify_admin.html')

###VERIFY VERIFICATION CODE
@app.route('/verify',methods=['GET','POST'])
@login_required
def verify():
	now_user=User.query.filter_by(email=current_user.email).first()
	if now_user.role!='admin':
		return redirect(url_for('user_menu'))
	if request.method=='POST':
		client_code=request.form['v-code']
		session['client_code']=client_code
		code=session.get('code')
		if int(code)== int(client_code):
			return redirect(url_for('admin'))
		else:
			return redirect(url_for('verify_admin'))
	return render_template('verify.html')

####TERMS AND CONDITIONS
@app.route('/terms')
def terms():
	return render_template('terms.html')


###ADMIN
@app.route('/admin')
@login_required
def admin():
	now_user=User.query.filter_by(email=current_user.email).first()
	if now_user.role!='admin':
		return redirect(url_for('user_menu'))
	else:
		return render_template('admin.html')

@app.route('/download_csv')
@login_required
def download_csv():
	now_user=User.query.filter_by(email=current_user.email).first()
	if now_user.role!='admin':
		return redirect(url_for('user_menu'))
	else:
		outfile=open('quick_SIN_demo.csv', 'w')
		outcsv=csv.writer(outfile)
		records=db.session.query(User).all()
		outcsv.writerow([column.name for column in User.__mapper__.columns])
		[ outcsv.writerow([ getattr(curr, column.name) for column in User.__mapper__.columns ]) for curr in records ]
		outfile.close()
		return send_file(outfile,mimetype='text/csv', attachment_filename='quick_SIN_demo.csv', as_attachment=True)


@app.route('/favicon.ico')
def	favicon():
	return	send_from_directory('/home/HearingSINTest/mysite/static', 'favicon.ico')

if __name__ == "__main__":
	app.run(debug=True)
