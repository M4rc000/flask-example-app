from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import ValidationError
from .models import User
from wtforms.validators import DataRequired, Email, EqualTo, Length

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=3, max=50)
    ])
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=30)
    ])
    email = StringField('Email', validators=[
        DataRequired(), Email(), Length(max=50)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(), Length(min=3)
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Submit')

class UpdateProfileForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=3, max=50)
    ])
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=30)
    ])
    email = StringField('Email', validators=[
        DataRequired(), Email(), Length(max=50)
    ])
    submit = SubmitField('Save')