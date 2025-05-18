from hashids import Hashids
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from flask import current_app, url_for
from app import mail

hashids = Hashids(min_length=8, salt='ArNoNA9123PLjHnKANEIams2NA')

def encode_id(id):
    return hashids.encode(id)

def decode_id(hashid):
    decoded = hashids.decode(hashid)
    return decoded[0] if decoded else None

def generate_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

def send_verification_email(user):
    token = user.email_token
    verify_url = url_for('auth.verify_email', token=token, _external=True)

    msg = Message('Confirm Your Email',
                  sender=current_app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'Hi {user.name},\n\nClick this link to verify your email:\n{verify_url}\n\nIf you did not register, ignore this email.'
    mail.send(msg)