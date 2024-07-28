from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo

#INICIO DE SESIÓN
class LoginForm(FlaskForm):
    username = StringField('Nombre de Usuario', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

#FORMULARIO DE REGISTRO
class RegisterForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired()])
    lastname = StringField('Apellido', validators=[DataRequired()])
    username = StringField('Nombre de usuario', validators=[DataRequired()])
    email = EmailField('Correo', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    confirm_password = PasswordField('Repetir Contraseña', 
                                     validators=[DataRequired(), 
                                                 EqualTo('password', 
                                                         message='Las contraseñas deben coincidir')])
    is_admin = BooleanField('¿Es administrador?')  # Nuevo campo
    submit = SubmitField('Registrarse')
