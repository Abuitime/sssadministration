import os
import re
import random
import hashlib
import hmac
import logging
import json
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class PageHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

class MainPage(PageHandler):
  def get(self):
      if self.request.get('user'):
        user = self.request.get('user')
        msg = ("Welcome" + user + "!")
        self.render("index.html", message = msg)
      else:
        self.response.write("hello world")
        #self.render("index.html", message = "")

  def post(self):
      pid = self.request.get('pid')
      if(len(pid) == 35):
        pid = pid[2:11]
      if not valid_pid(pid):
        msg = 'Invalid PID'
        self.render('index.html', message = msg)   
           
      u = User.login(pid)
      if u:
        msg = ("Welcome" + u.name + "!")
        # aad user to event model or whatever we're using to keep track of members
        self.render('index.html', message = msg)
      else:
        self.redirect('/signup?pid=%s' %(pid))

class User(db.Model):
    pid = db.StringProperty(required = True)
    name = db.StringProperty(required = True)
    last_name = db.StringProperty(required = True)
    major = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    number = db.StringProperty(required = True)
    year = db.StringProperty(required = True)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    @classmethod
    def by_pid(cls, pid):
        u = User.all().filter('pid =', pid).get()
        return u
    @classmethod
    def register(cls, pid, name, last_name, major, email, number, year):
        return User(pid = pid,
                    name = name,
                    last_name = last_name,
                    major = major,
                    email = email,
                    number = number,
                    year = year)

    @classmethod
    def login(pid):
        u = cls.by_pid(pid)
        return u

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
def valid_pid(pid):
    if len(pid) != 8:
        return False
    return True 

class Signup(PageHandler):
    def get(self):
        self.render("signup.html", pid = self.request.get('pid'))

    def post(self):
        have_error = False
        self.name = self.request.get('name')
        self.last_name = self.request.get('last_name')
        self.pid = self.request.get('pid')
        self.email = self.request.get('email')
        self.major = self.request.get('major')
        self.year = self.request.get('year')
        self.number = self.request.get('number')

        params = dict(name = self.username,
                      last_name = self.last_name,
                      pid = self.pid,
                      email = self.email,
                      major = self.major,
                      year = self.year,
                      number = self.number
                      )

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        if not valid_pid(self.pid):
            params['error_pid'] = "That's not a valid PID"
            have_error = True
        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_pid(self.pid)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_exists = msg)
        else:
            u = User.register(self.pid, self.name, self.last_name, self.major, self.email, self.number, self.year)
            u.put()

            self.login(u)
            self.redirect('/?user=%s' %(u.name))

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Register),
                               ],
                              debug=True)
