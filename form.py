from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, EqualTo, Length

class RegisterForm(FlaskForm):
    """定义表单类"""
    username = StringField(label=u"用户名", validators=[DataRequired(u"用户名不能为空")])
    password = PasswordField(label=u"密码", validators=[DataRequired(u"密码不能为空"), Length(8, 128)])
    password1 = PasswordField(label=u"验证密码", validators=[DataRequired(u"验证密码不能为空"), EqualTo("password", u"两次密码不一样")])
    phone = IntegerField('手机号', validators=[DataRequired()])
    submit = SubmitField(label=u"提交")

