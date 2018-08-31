from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length

class LoginForm(FlaskForm):
	username = StringField('Username',validators=[InputRequired(),Length(min=4,max=20)])
	password = PasswordField('Password',validators=[InputRequired(),Length(min=5,max=80)])
	remember = BooleanField('Remember Me')

class RegistrationForm(FlaskForm):
	username = StringField('Username',validators=[InputRequired(),Length(min=4,max=20)])
	email = StringField('Email',validators=[InputRequired(),Email(message="Invalid Email"),Length(min=3,max=80)])
	password = PasswordField('Password',validators=[InputRequired(),Length(min=5,max=80)])
