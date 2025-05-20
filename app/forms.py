from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import ValidationError
from .models import User
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField, HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=50)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    picture = FileField('Picture', validators=[Optional()])
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
    picture = FileField('Profile Picture', validators=[
        Optional()
    ])
    submit = SubmitField('Save')

class EditManageUserForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=3, max=50)
    ])
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=30)
    ])
    email = StringField('Email', validators=[
        DataRequired(), Email(), Length(max=50)
    ])
    password = StringField('Password', validators=[
        DataRequired(), Length(max=255)
    ])
    is_active = SelectField(
        'Status',
        choices=[('1', 'Active'), ('0', 'Not Active')],
        validators=[DataRequired()]
    )
    submit = SubmitField('Save')
class ShowManageUserForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=3, max=50)
    ])
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=30)
    ])
    email = StringField('Email', validators=[
        DataRequired(), Email(), Length(max=50)
    ])
    is_active = StringField('Status', validators=[
        DataRequired(), Length(max=50)
    ])

class AddManageUserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=50)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3)])
    submit = SubmitField('Save')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ForgotPasswordInputForm(FlaskForm):
    email = HiddenField('Email')
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Save')

class BookMovieForm(FlaskForm):
    movie_showing_id = HiddenField('movie_showing_id')
    seat_id = StringField('Seat No', validators=[DataRequired()])
    teater_no = StringField('Teater No', validators=[DataRequired()]) 
    user_id = HiddenField('user_id')
    status_payment = HiddenField('status_payment')
    submit = SubmitField('Save')