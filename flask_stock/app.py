# coding = utf-8
"""
@author: zhou
@time:2019/11/7 11:22
@File: app.py
"""

from flask import Flask, render_template, request, abort, session, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from pyecharts import options as opts
from pyecharts.charts import Kline
import tushare as ts
import pandas as pd
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
import time


app = Flask(__name__)
app.secret_key = 'A Hard String'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + 'myweb.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'


@login_manager.user_loader
def load_user(user_id):
    return WebUser.query.get(int(user_id))


# 用户表结构
class WebUser(UserMixin, db.Model):
    __tablename__ = 'webuser'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))

    @staticmethod
    def insert_user():
        users = {
            'user1': ['user1@luobo.com', 'test1', 1],
            'user2': ['user2@luobo.com', 'test2', 1],
            'admin1': ['admin1@luobo.com', 'admin1', 2],
            'admin2': ['admin2@luobo.com', 'admin2', 2]
        }
        for u in users:
            user = WebUser.query.filter_by(username=u[0]).first()
            if user is None:
                user = WebUser(user_id=time.time(), username=u, email=users[u][0])
                user.password = users[u][1]
                db.session.add(user)
            db.session.commit()

    @property
    def password(self):
        raise AttributeError('You can not read the password')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        if self.password_hash is not None:
            return check_password_hash(self.password_hash, password)


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired(),
                                                     EqualTo('confirm_pw', message='两次输入的密码需要一致!')])
    confirm_pw = PasswordField('confirm password', validators=[DataRequired()])
    submit = SubmitField('Submit')

    def validate_email(self, field):
        if WebUser.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱已经存在!')


@app.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = WebUser.query.filter_by(email=email).first()
        if user is None:
            newuser = WebUser(email=email, username=email, password=password, user_id=time.time())
            db.session.add(newuser)
            flash("你可以登陆啦！")
            return redirect(url_for('login'))
        flash("邮箱已经存在！")
    return render_template('register.html', form=form)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = WebUser.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
            flash('欢迎回来！')
            return redirect(request.args.get('next') or url_for('index'))
        flash('用户名或密码不正确！')
    return render_template('login.html', form=form)


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


def get_stock_data(code, ctime):
    df = ts.get_hist_data(code)
    mydate = df[:ctime].index.tolist()
    mydata = df[:ctime][['open', 'close', 'low', 'high']].values.tolist()
    return [mydate, mydata]


def kline_base(mydate, data, name) -> Kline:
    c = (
        Kline()
        .add_xaxis(mydate)
        .add_yaxis("%s" % name, data)
        .set_global_opts(
            yaxis_opts=opts.AxisOpts(is_scale=True,
                                    splitarea_opts=opts.SplitAreaOpts(
                    is_show=True, areastyle_opts=opts.AreaStyleOpts(opacity=1)
                ),
            ),
            xaxis_opts=opts.AxisOpts(is_scale=True,
                                    axislabel_opts=opts.LabelOpts(rotate=-30)),
            title_opts=opts.TitleOpts(title="股票走势"),
            datazoom_opts=[opts.DataZoomOpts()],
            toolbox_opts=opts.ToolboxOpts(is_show=True),
        )
    )
    return c


@app.route("/")
def index():
    return render_template("index.html")


def check_stock(code):
    n = 0
    l = []
    stock_code = pd.read_csv("stock_code_name.csv", dtype=object)
    stock_code.drop('Unnamed: 0', axis=1, inplace=True)
    stock_list = stock_code.values.tolist()
    for i in stock_list:
        if code in i:
            n += 1
            l = i
        else:
            continue
    return n, l


@app.route("/Kline", methods=['GET', 'POST'])
def get_kline_chart():
    stock_name = request.form.get('stockName')
    query_time = request.form.get('queryTime')
    if int(query_time) > 30:
        if current_user.is_authenticated:
            pass
        else:
            abort(403)
    if not stock_name:
        stock_name = '平安银行'
    if not query_time:
        query_time = 30
    status, stock_code = check_stock(stock_name)
    if status == 0:
        return 'error stock code or name'
    mydate, mydata = get_stock_data(stock_code[0], int(query_time))
    c = kline_base(mydate, mydata, stock_code[1])
    return c.dump_options()


if __name__ == '__main__':
    app.run(debug=True)
