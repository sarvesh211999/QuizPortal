from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from pickle import loads, dumps
from db_create import *
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from random import randint
import json
import os


app = Flask(__name__)
app.config['SECRET_KEY']= 'asjbfjasbiadbvudbraskbvdksbcf1w2e3r2ru23180u0'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from models import *
from forms import *

admin = Admin(app,index_view=MyAdminIndexView(name="Home",template='admin/index.html'))
admin.add_view(ModelView(user,db.session,name="User"))
admin.add_view(ModelView(Feedback,db.session,name="Feedbacks"))
admin.add_view(ModelView(Quiz,db.session))
admin.add_view(RuleView(Problems,db.session))
admin.add_view(ModelView(Category,db.session))
admin.add_view(ModelView(Sub_Category,db.session,name="SubCategory"))

def init_db():
	db.init_app(app)
	db.drop_all()
	db.create_all()

def get_auth(state=None,token=None):
	if token:
		return OAuth2Session(Auth.CLIENT_ID,token=token)
	if state:
		return OAuth2Session(Auth.CLIENT_ID,state=state,token=token,redirect_uri=Auth.REDIRECT_URL)

	oauth2 = OAuth2Session(Auth.CLIENT_ID,redirect_uri=Auth.REDIRECT_URL,scope=Auth.SCOPE)
	return oauth2


@app.route('/googleCallBack')
@login_required
def googleCallBack():
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('home'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error'
    else:
        google = get_auth(state=session['oauth-state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            user_query = user.query.filter_by(email=email).first()
            if user_query is None:
                user_query = user()
                user_query.email = email
            user_query.username = user_data['name']
            user_query.token = json.dumps(token)
            db.session.add(user_query)
            db.session.commit()
            login_user(user_query)
            return redirect(url_for('home'))
        return 'Could not fetch your information.'

@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))

@app.route('/')
def index():
	return redirect('/home')

@app.route('/home')
def home():
	adminflag =0 

	if current_user.is_anonymous :
		signinupflag = 1
	else:
		signinupflag = 0

	category = Category.query.all()
	subcategories = Sub_Category.query.all()

	to_send = {}
	for i in category:
		to_send[i]=[]
	for i in category:
		temp = db.session.query(category_subcategory_relation).filter(category_subcategory_relation.c.category_id==i.id).all()
		for j in temp:
			temp2=Sub_Category.query.filter_by(id=j[1]).first()
			to_send[i].append(temp2)
	score_display = user.query.order_by(user.total_score.desc()).all()

	if signinupflag == 0:
		if current_user.id == 1:
			adminflag = 1
	else:
		adminflag = 0


	return render_template('home.html',to_send=to_send,score_display=score_display,adminflag=adminflag,signinupflag=signinupflag)

@app.route('/quiz_dashboard')
@login_required
def quiz_dashboard():

	if current_user.is_anonymous :
		signinupflag = 1
	else:
		signinupflag = 0


	if current_user.id == 1:
		adminflag = 1
	else:
		adminflag = 0
	category = Category.query.all()
	subcategories = Sub_Category.query.all()
	to_send = {}
	for i in category:
		to_send[i]={}

	attempt = {}
	attempt_run = {}
	total_score={}

	for i in category:
		temp = db.session.query(category_subcategory_relation).filter(category_subcategory_relation.c.category_id==i.id).all()

		for j in temp:
			temp2 = Sub_Category.query.filter_by(id=j[1]).first()
			temp3 = Category.query.filter_by(id=j[0]).first()
			to_send[temp3][temp2]={}

			for k in subcategories:
				temp4 = db.session.query(subcategory_quiz_relation).filter(subcategory_quiz_relation.c.sub_category_id==temp2.id).all()
			
			for l in temp4:
			
				temp5 = Sub_Category.query.filter_by(id=l[0]).first()
				temp6 = Quiz.query.filter_by(id=l[1]).first()
				to_send[temp3][temp5][temp6]=[]
				if(Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=temp6.id).all()):
					pass
				else:
					new_score_row = Score_Table(user_id=current_user.id,quiz_id=temp6.id,attempted=0,score=0)
					db.session.add(new_score_row)
					db.session.commit()


				score_query = Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=temp6.id).first()
				to_send[temp3][temp5][temp6].append(score_query.score)
				attempt[temp6.id] = score_query.attempted
				total_score[temp6.id]=[]
				total = Runs.query.filter_by(user_id=current_user.id).filter_by(quid_id=temp6.id).all()
				total_score[temp6.id].append(len(total)*10)

	return render_template('quiz_dashboard.html',to_send=to_send,attempt=attempt,total_score=total_score,adminflag=adminflag,signinupflag=signinupflag)


@app.route('/quiz/<int:quizid>/<int:page>')
@login_required
def quiz(page=1,quizid=1):
	if current_user.is_anonymous :
		signinupflag = 1
	else:
		signinupflag = 0

	if current_user.id == 1:
		adminflag = 1
	else:
		adminflag = 0
	per_page = 1
	to_send = []
	attempt ={}
	temp1 = db.session.query(relation).with_entities(relation.c.problem_id).filter(relation.c.quiz_id==quizid).all()
	check = Runs.query.filter_by(user_id=current_user.id).filter_by(quid_id=quizid).all()

	attempt_query = Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=quizid).first()
	if attempt_query.attempted == 2:
		pass
	else:
		attempt_query.attempted = 1
	db.session.commit()
	attempt[quizid]=[]
	attempt[quizid].append(attempt_query.attempted)
	for i in range(len(temp1)):
		
		if(Runs.query.filter_by(user_id=current_user.id).filter_by(quid_id=quizid).filter_by(problem_id=temp1[i][0]).first()):
			pass
		else:
			new_row = Runs(user_id=current_user.id,quid_id=quizid,problem_id=temp1[i][0])
			db.session.add(new_row)
			db.session.commit()

	if(Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=quizid).all()):
		pass
	else:
		new_score_row = Score_Table(user_id=current_user.id,quiz_id=quizid,attempted=0,score=0)
		db.session.add(new_score_row)
		db.session.commit()

	for i in temp1:
		to_send.append(i[0])
	temp = Problems.query.filter(Problems.id.in_(to_send)).paginate(page,per_page,error_out=False)

	lifeline_query = Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=quizid).first()
	lifelinedisable = lifeline_query.lifeline

	number = len(check)

	return render_template('quiz.html',lifeline=lifelinedisable,problems=temp,quizid_send=quizid,check=check,length=number,attempt=attempt,adminflag=adminflag,signinupflag=signinupflag)


@app.route('/login',methods=['GET','POST'])
def login():

	print(current_user)

	if current_user.is_anonymous :
		signinupflag = 1
	else:
		signinupflag = 0

	if current_user.is_authenticated:
		return redirect(url_for('home'))
	google = get_auth()
	auth_url , state = google.authorization_url(Auth.AUTH_URI,access_type='offline')
	session['oauth-state'] = state


	form = LoginForm()
	form2 = RegistrationForm()
	userlogin = user.query.filter_by(username=form.username.data).first()
	if form.validate_on_submit():
		if userlogin:

			if check_password_hash(userlogin.password,form.password.data):
				login_user(userlogin,remember=form.remember.data)
				return redirect('/home')

		flash("Incorrect password or username")

	return render_template('login_temp.html',form=form,form2=form2,flag=0,signinupflag=signinupflag,auth_url=auth_url)

@app.route('/signup',methods=['GET','POST'])
def signup():
	if current_user.is_anonymous :
		signinupflag = 1
	else:
		signinupflag = 0
	form = LoginForm()
	form2 = RegistrationForm()
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	google = get_auth()
	auth_url , state = google.authorization_url(Auth.AUTH_URI,access_type='offline')
	session['oauth-state'] = state

	if form2.validate_on_submit():
		hashed_password = generate_password_hash(form2.password.data,method='sha256')
		if user.query.filter_by(username=form2.username.data).first():
			flash("Username already exist")
			return render_template('login_temp.html',form=form,form2=form2,flag=1,signinupflag=signinupflag)
		if user.query.filter_by(email=form2.email.data).first():
			flash("Email-id already exist")
			return render_template('login_temp.html',form=form,form2=form2,flag=1,signinupflag=signinupflag)
		new_user = user(username=form2.username.data,email=form2.email.data,password=hashed_password,role=False)
		db.session.add(new_user)
		db.session.commit()
		flash('Login with username and password')
		return redirect('/login')

	return render_template('login_temp.html',form=form,form2=form2,flag=1,signinupflag=signinupflag)

@app.route('/check')
@login_required
def check():
	if current_user.id == 1:
		adminflag = 1
	else:
		adminflag = 0
	flag=0;
	to_check = []
	id1 = request.args.get('id_sent',0,type=int)
	quiz_id_received = request.args.get('quiz_id_sent',0,type=int)

	value = json.loads(request.args.get('value'))

	flag_option1=0;
	flag_option2=0;
	flag_option3=0;
	flag_option4=0;
	for x in value:
		if x == '1':
			flag_option1=2
		if x == '2':
			flag_option2=2
		if x == '3':
			flag_option3=2
		if x == '4':
			flag_option4=2
		

	problem = Problems.query.filter_by(id=id1).first()
	run_query = Runs.query.filter_by(user_id=current_user.id).filter_by(quid_id=quiz_id_received).filter_by(problem_id=id1).first()
	run_query.attempted =True
	db.session.commit()
	if problem.answer_first == True:
		to_check.append('1')
		flag_option1=1;
		if '1' in value:
			pass
		else:
			flag=1

	if problem.answer_second == True:
		to_check.append('2')
		flag_option2=1;
		if '2' in value:
			pass
		else:
			flag=1
		
	if problem.answer_third == True:
		to_check.append('3')
		flag_option3=1;
		if '3' in value:
			pass
		else:
			flag=1
		
	if problem.answer_fourth == True:
		to_check.append('4')
		flag_option4=1;
		if '4' in value:
			pass
		else:
			flag=1

	if to_check==value:
		flag = 0
	else:
		flag = 1

	if flag == 0:
		score_query = Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=quiz_id_received).first()
		if score_query.attempted !=2 :
			score_query.score += 10;
			db.session.commit()

	return jsonify(flag=1,flag_option1=flag_option1,flag_option2=flag_option2,flag_option3=flag_option3,flag_option4=flag_option4)

@app.route('/changepass')
@login_required
def changepass():
	flag=0

	if check_password_hash(current_user.password,request.args.get('curr')):
		if request.args.get('pass1') == request.args.get('pass2'):
			user_query = user.query.filter_by(id=current_user.id).first()
			user_query.password = generate_password_hash(request.args.get('pass1'),method='sha256')
			db.session.commit()
		else:
			flag=1
	else:
		flag=2

	return jsonify(flag=flag)


@app.route('/submit/<int:quizid>')
@login_required
def submit(quizid=1):
	if current_user.id == 1:
		adminflag = 1
	else:
		adminflag = 0


	score_query = Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=quizid).first()
	if score_query.attempted != 2:
		score_query.attempted = 2
		user_query  = user.query.filter_by(id=current_user.id).first()
		user_query.total_score += score_query.score
		db.session.commit()
	else:
		pass

	total = Runs.query.filter_by(user_id=current_user.id).filter_by(quid_id=quizid).all()
	notattempted = Runs.query.filter_by(user_id=current_user.id).filter_by(quid_id=quizid).filter_by(attempted=0).all()
	correct = int(score_query.score) / 10
	incorrect = len(total) - len(notattempted) - correct

	return render_template('quiz_result.html',correct=int(correct),incorrect=int(incorrect),notattempted=len(notattempted),adminflag=adminflag)

@app.route('/lifeline')
def lifeline():
	quizid = request.args.get('quiz_id_sent')
	score_query =  Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=quizid).first()
	score_query.lifeline = True
	db.session.commit()
	return jsonify()

@app.route('/feedback')
def feedback():
	feedback = Feedback(name=request.args.get('name'),email=request.args.get('email'),feedback=request.args.get('msg'))
	db.session.add(feedback)
	db.session.commit()
	return jsonify()

@app.route('/profile')
@login_required
def profile():
	if current_user.is_anonymous :
		signinupflag = 1
	else:
		signinupflag = 0


	if current_user.id == 1:
		adminflag = 1
	else:
		adminflag = 0
	category = Category.query.all()
	subcategories = Sub_Category.query.all()
	to_send = {}
	for i in category:
		to_send[i]={}

	attempt = {}
	attempt_run = {}
	total_score={}




	for i in category:
		temp = db.session.query(category_subcategory_relation).filter(category_subcategory_relation.c.category_id==i.id).all()
		for j in temp:
			temp2 = Sub_Category.query.filter_by(id=j[1]).first()
			temp3 = Category.query.filter_by(id=j[0]).first()
			to_send[temp3][temp2]={}

			for k in subcategories:
				temp4 = db.session.query(subcategory_quiz_relation).filter(subcategory_quiz_relation.c.sub_category_id==temp2.id).all()
			
			for l in temp4:
			
				temp5 = Sub_Category.query.filter_by(id=l[0]).first()
				temp6 = Quiz.query.filter_by(id=l[1]).first()
				to_send[temp3][temp5][temp6]=[]
				if(Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=temp6.id).all()):
					pass
				else:
					new_score_row = Score_Table(user_id=current_user.id,quiz_id=temp6.id,attempted=0,score=0)
					db.session.add(new_score_row)
					db.session.commit()


				score_query = Score_Table.query.filter_by(user_id=current_user.id).filter_by(quiz_id=temp6.id).first()
				to_send[temp3][temp5][temp6].append(score_query.score)
				attempt[temp6.id] = score_query.attempted
				total_score[temp6.id]=[]
				total = Runs.query.filter_by(user_id=current_user.id).filter_by(quid_id=temp6.id).all()
	user = []
	username = current_user.username
	user_email = current_user.email
	return render_template('profile.html',to_sent=to_send,attempt=attempt,username=username,user_email=user_email)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect('/home')

@app.route('/sendmail')
def send():
	fromaddr = "skdfbskdfbkudfykgiyifiybaubaifiyv"
	toaddr = request.args.get('email')
	user_query = user.query.filter_by(email=toaddr).first()	
	range_start = 10**(5)
	range_end = (10**6)-1
	number = randint(range_start, range_end)
	user_query.code = number
	db.session.commit()
	text = "Your verfication code is " + str(number) 
	server = smtplib.SMTP('smtp.gmail.com', 587)
	server.starttls()
	server.login(fromaddr, "etouwhduofhouahdfouhduofb")
	server.sendmail(fromaddr, toaddr, text)
	server.quit()
	return jsonify()



@app.route('/forgot_pass')
def for_pass():
	if current_user.is_anonymous :
		signinupflag = 1
	else:
		signinupflag = 0

	return render_template('for_pass2.html',signinupflag=signinupflag)


@app.route('/change_pass',methods=['GET','POST'])
def change_pass():
	if current_user.is_anonymous :
		signinupflag = 1
	else:
		signinupflag = 0

	email =  request.args.get('email')
	user_query = user.query.filter_by(email=email).first()
	code = user_query.code
	json_helper ={}
	json_helper['email']=email
	json_object = json.dumps(json_helper) 
	return render_template('for_pass1.html',signinupflag=signinupflag,verificationcode=code,email=json_object)

@app.route('/changepass_success')
def changepass_success():
	user_query= user.query.filter_by(email=request.args.get('email')).first()
	user_query.password = generate_password_hash(request.args.get('pwd1'),method='sha256')
	db.session.commit()
	return jsonify()

if __name__=='__main__':

	# init_db()
	# insert()
	app.run(debug=True)
