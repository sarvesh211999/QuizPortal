from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from quiz import db

# relation = db.Table('relation',
# 	db.Column('quiz_id',db.Integer(),db.ForeignKey('quizes.id')),
# 	db.Column('problem_id',db.Integer(),db.ForeignKey('users.id'))
# )

class Auth:
	CLIENT_ID = '647353834548-lkb2hl6qack5k2afdoh7j8sl2nv526dc.apps.googleusercontent.com'
	CLIENT_SECRET = 'A3Gc1SwE1HSLK5AIsREVZOoM'
	REDIRECT_URL = 'http://127.0.0.1:5000/googleCallBack'
	AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
	TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
	USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
	SCOPE = ['profile','email']

class user(UserMixin,db.Model):
	id = db.Column(db.Integer,primary_key=True)
	username = db.Column(db.String(20),unique=True)
	email = db.Column(db.String(80),unique=True)
	password = db.Column(db.String(80))
	role = db.Column(db.Boolean,default=False)
	token = db.Column(db.Text)
	total_score = db.Column(db.Integer,default=0)
	code = db.Column(db.Integer,default=0)
	def __repr__(self):
		return self.username


class Problems(db.Model):
	__tablename__ = 'problems'
	id = db.Column(db.Integer,primary_key=True)
	statement = db.Column(db.String(100),unique=True)
	option_first = db.Column(db.String(100))
	option_second = db.Column(db.String(100))
	option_third = db.Column(db.String(100))
	option_fourth = db.Column(db.String(100))
	answer_first = db.Column(db.Boolean,default=False)
	answer_second = db.Column(db.Boolean,default=False)
	answer_third = db.Column(db.Boolean,default=False)
	answer_fourth = db.Column(db.Boolean,default=False)
	type_of_ques = db.Column(db.Boolean,default=False) #if True then MCQ else SCQ
	attempted = db.Column(db.Boolean,default=False)

	def __repr__(self):
		return self.statement

relation = db.Table('relation',
	db.Column('quiz_id',db.Integer(),db.ForeignKey('quizes.id')),
	db.Column('problem_id',db.Integer(),db.ForeignKey('problems.id'))
)

category_subcategory_relation = db.Table('category_subcategory_relation',
	db.Column('category_id',db.Integer(),db.ForeignKey('category.id')),
	db.Column('sub_category_id',db.Integer(),db.ForeignKey('sub_category.id'))
	)
subcategory_quiz_relation = db.Table('subcategory_quiz_relation',
	db.Column('sub_category_id',db.Integer(),db.ForeignKey('sub_category.id')),
	db.Column('quiz_id',db.Integer(),db.ForeignKey('quizes.id')),
	)

class Quiz(db.Model):
	__tablename__ = 'quizes'
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(100))
	# quiz_id = db.Column(db.Integer(),db.ForeignKey('problems.id'))
	problem = db.relationship('Problems',secondary=relation,backref='quizes')
	def __repr__(self):
		return self.name

class Category(db.Model):
	__tablename__ = 'category'
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(100))
	def __repr__(self):
		return self.name

class Sub_Category(db.Model):
	__tablename__ = 'sub_category'
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(100))
	categories = db.relationship('Category',secondary=category_subcategory_relation,backref='sub_category')
	quiz = db.relationship('Quiz',secondary=subcategory_quiz_relation,backref='sub_category')
	def __repr__(self):
		return self.name

class Runs(db.Model):
	__tablename__ = 'runs'
	id = db.Column(db.Integer,primary_key=True)
	user_id = db.Column(db.Integer)
	quid_id = db.Column(db.Integer)
	problem_id = db.Column(db.Integer)
	attempted = db.Column(db.Boolean,default=False)

class Score_Table(db.Model):
	__tablename__ = 'score_table'
	id = db.Column(db.Integer,primary_key=True)
	user_id = db.Column(db.Integer)
	quiz_id = db.Column(db.Integer)
	attempted = db.Column(db.Integer,default=0)
	score = db.Column(db.Integer)
	lifeline = db.Column(db.Boolean,default= False)

class Feedback(db.Model):
	__tablename__ = 'feedback'
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(100))
	email = db.Column(db.String(100))
	feedback = db.Column(db.String(300))

class RuleView(ModelView):
	 column_labels = {'type_of_ques': 'Tick for MCQ    Blank for SCQ'}

class MyModelView(ModelView):

	def is_accessible(self):
		if current_user.is_anonymous is not True:
			if current_user.role == True:
				return True

			return False
		return False

	def inaccessible_callback(self,name, **kwargs):
		return redirect(url_for('login'))

class MyAdminIndexView(AdminIndexView):

	def is_accessible(self):
		if current_user.is_anonymous is not True:
			if current_user.role == True:
				return True

			return False
		return False

		return current_user.is_authenticated

	def inaccessible_callback(self,name,**kwargs):
		return redirect(url_for('login'))
