import os
import re
import random
import hashlib
import hmac
import logging
import datetime
from string import letters
import HTMLParser
import webapp2
import jinja2
import unicodedata
from google.appengine.ext import db
from webapp2_extras import sessions

#Facebook Dependencies Start
FACEBOOK_APP_ID = "173288699538562"
FACEBOOK_APP_SECRET = "4b4ff6763f2cb145500ca87c3be8b295"

import facebook
import webapp2
import os
#import jinja2
import urllib2

#from google.appengine.ext import db
from webapp2_extras import sessions

config = {}
config['webapp2_extras.sessions'] = dict(secret_key='')
#Facbook Dependencies End

template_dir = os.path.join(os.path.dirname(__file__), 'views')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True,
                               extensions = ['jinja2.ext.autoescape'])

key = 'KDdwpDV9jB'
secret = 'abamjlrr'
input_key = """
            <div class="6u">
            <input class="text" type="text" name="key" id="key" value="" placeholder="Key" />
            </div>
            <div class="6u">
            <input class="text" type="text" name="password" id="password" value="" placeholder="Password" />
            </div>
            """
#html_parser = HTMLParser.HTMLParser()
#input_key = html_parser.unescape(input_key)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class PageHandler(webapp2.RequestHandler):
    def admin_auth(self):
        admin = self.request.cookies.get('admin')
        password = self.request.cookies.get('password')
        if admin and password:
            if check_secure_val(admin) and check_secure_val(password):
                return True
        return False 
        self.redirect('/')   
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        #params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'admin=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'password=; Path=/')
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()

class MainPage(PageHandler):
  def get(self):
      if self.request.get('user'):
        user = self.request.get('user')
        msg = ("Welcome " + user + "!")
        self.render("index.html", message = msg)
      else:
        #self.response.write("hello world")
        self.render("index.html", message = "")

  def post(self):
      pid = self.request.get('pid')
      if(len(pid) == 35):
        pid = pid[2:10]
      if not valid_pid(pid):
        msg = 'Invalid PID'
        self.render('index.html', message = msg)   
      else:
        u = User.login(pid)
        if u:
          msg = ("Welcome " + u.name + "!")
          self.render('index.html', message = msg)
        else:
          self.redirect('/signup?pid=%s' %(pid))
class Event(db.Model):
    name = db.StringProperty(required = True)
    date = db.StringProperty(required = True)
    location = db.StringProperty(required = True)
    description = db.Text
    participants = db.Text

    @classmethod
    def create(cls, name, date, location, description, participants):
        return User(name = name,
                    date = date,
                    location = location,
                    description = description,
                    participants = participants)

    def by_date(cls, date):
        e = Event.all().filter('date =', date).get()
        return e

    def by_name(cls, name):
        e = Event.all().filter('name =', name).get()
        return e

class User(db.Model):
    pid = db.StringProperty(required = True)
    name = db.StringProperty(required = True)
    last_name = db.StringProperty(required = True)
    major = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    number = db.StringProperty(required = True)
    year = db.StringProperty(required = True)
    admin = db.BooleanProperty()
    password = db.StringProperty(required = True)
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    @classmethod
    def by_pid(cls, pid):
        u = User.all().filter('pid =', pid).get()
        return u
    @classmethod
    def register(cls, pid, name, last_name, major, email, number, year, admin, password):
        return User(pid = pid,
                    name = name,
                    last_name = last_name,
                    major = major,
                    email = email,
                    number = number,
                    year = year,
                    admin = admin,
                    password = password)

    @classmethod
    def login(cls, pid):
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
def valid_number(number):
    if len(number) != 10:
        return False
    return True
class Signup(PageHandler):
    def get(self):
        if User.all().count() == 0 or self.admin_auth():
            params = dict()
            params['key'] = input_key
            if self.request.get('pid'):
                params['pid'] = self.request.get('pid')
            self.render("signup.html", **params)

        elif self.request.get('pid'):
            self.render("signup.html", pid = self.request.get('pid'))

        else:
            self.render("index.html", message = "please enter your PID")

    def post(self):
        have_error = False
        self.name = self.request.get('name')
        self.last_name = self.request.get('last_name')
        self.pid = self.request.get('pid')
        self.email = self.request.get('email')
        self.major = self.request.get('major')
        self.year = self.request.get('year')
        self.number = self.request.get('number')
        self.admin = False
        self.password = ""

        params = dict(name = self.name,
                      last_name = self.last_name,
                      pid = self.pid,
                      email = self.email,
                      major = self.major,
                      year = self.year,
                      number = self.number,
                      )
        if not self.name or not self.last_name:
            params['error_name'] = "That's not a complete name."
            have_error = True
        if not self.major:
            params['error_major'] = "Please select a major."
            have_error = True
        if not self.year:
            params['error_year'] = "Please select your year."
            have_error = True
        if User.all().count() == 0 and not valid_password(self.password):
            params['error_password'] = "That is not a valid password."

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        if not valid_pid(self.pid):
            params['error_pid'] = "That's not a valid PID."
            have_error = True
        if not valid_number(self.number):
            params['error_number'] = "That's not a valid phone number."
            have_error = True
        if self.admin_auth() or User.all().count() == 0:
            if self.request.get("key") and self.request.get("key") == key:
                self.admin = True
                self.password = self.request.get("password")
            else:
                have_error = True
        if have_error:
            if self.admin_auth() or User.all().count() == 0:
                params['key'] = input_key
                self.render('signup.html', **params)
            else:
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
            if self.admin_auth():
                self.render('signup.html', error_exists = msg, key = input_key)
            else: 
                self.render('signup.html', error_exists = msg)
        else:
            self.password = make_pw_hash(self.pid, self.password)
            u = User.register(self.pid, self.name, self.last_name, self.major, self.email, self.number, self.year, self.admin, self.password)
            u.put()

            if self.admin_auth():
                self.redirect('/admin/tools?msg=User_Added')
            else:
                User.login(u)
                self.redirect('/?user=%s' %(u.name))

class Admin(PageHandler):
    def get(self):
        if(User.all().count() == 0):
            self.redirect('/signup')
        self.render('admin_login.html')
    def post(self):
        admin = self.request.get('admin')
        if admin:
            u = User.by_pid(admin)
            password = self.request.get('password')
            if u and password:
                if valid_pw(admin, password, u.password):
                    self.dispatch()
                    self.session['admin'] = True
                    message = "Welcome"
                    self.redirect('/admin/tools?msg=%s'%(message))

        self.render('admin_login.html', error = "Invalid Login")

class Tools(PageHandler):
    def get(self):
        if self.session.get('admin'):
            msg = self.request.get('msg')
            self.render('tools.html', message = msg)
        else:
            self.redirect("/admin")

class Management(PageHandler):
    def get(self):
        if self.admin_auth():
            self.render('mgmt.html')
        else:
            self.redirect("/admin")

class Event(PageHandler):
    def get(self):
        if self.admin_auth():
            self.render("event.html")
        else:
            self.redirect('/admin')
    def post(self):
        if self.admin_auth():
            name = self.request.get('name')
            date = self.request.get('date')
            location = self.request.get('location')
            description = self.request.get('description')
            if(name and date and location and description):
                e = Event.create(name, date, location, description)
                e.put()
                self.redirect("/admin/tools?msg=Event_Created")
            else:
                self.render("event.html", name = name, date = date, 
                            location = location, description = description,
                            error = "invalid information")
        else:
            self.redirect('/admin')

class Logout(PageHandler):
    def get(self):
        self.logout()
        self.redirect('/')

#Facebook Classes Start
class FacebookUser(db.Model):
    id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    name = db.StringProperty(required=True)
    profile_url = db.StringProperty(required=True)
    access_token = db.StringProperty(required=True)


class FacebookBaseHandler(webapp2.RequestHandler):
    """Provides access to the active Facebook user in self.current_user

    The property is lazy-loaded on first access, using the cookie saved
    by the Facebook JavaScript SDK to determine the user ID of the active
    user. See http://developers.facebook.com/docs/authentication/ for
    more information.
    """
    @property
    def current_user(self):
        if self.session.get("user"):
            # User is logged in
            return self.session.get("user")
        else:
            # Either used just logged in or just saw the first page
            # We'll see here
            cookie = facebook.get_user_from_cookie(self.request.cookies,
                                                   FACEBOOK_APP_ID,
                                                   FACEBOOK_APP_SECRET)
            if cookie:
                # Okay so user logged in.
                # Now, check to see if existing user
                user = User.get_by_key_name(cookie["uid"])
                if not user:
                    # Not an existing user so get user info
                    graph = facebook.GraphAPI(cookie["access_token"])
                    profile = graph.get_object("me")
                    user = FacebookUser(
                        key_name=str(profile["id"]),
                        id=str(profile["id"]),
                        name=profile["name"],
                        profile_url=profile["link"],
                        access_token=cookie["access_token"]
                    )
                    user.put()
                elif user.access_token != cookie["access_token"]:
                    user.access_token = cookie["access_token"]
                    user.put()
                # User is now logged in
                self.session["user"] = dict(
                    name=user.name,
                    profile_url=user.profile_url,
                    id=user.id,
                    access_token=user.access_token
                )
                return self.session.get("user")
        return None

    def dispatch(self):
        """
        This snippet of code is taken from the webapp2 framework documentation.
        See more at
        http://webapp-improved.appspot.com/api/webapp2_extras/sessions.html

        """
        self.session_store = sessions.get_store(request=self.request)
        try:
            webapp2.RequestHandler.dispatch(self)
        finally:
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        """
        This snippet of code is taken from the webapp2 framework documentation.
        See more at
        http://webapp-improved.appspot.com/api/webapp2_extras/sessions.html

        """
        return self.session_store.get_session()


class FacebookHomeHandler(FacebookBaseHandler):
    def get(self):
        template = jinja_environment.get_template('example.html')
        self.response.out.write(template.render(dict(
            facebook_app_id=FACEBOOK_APP_ID,
            current_user=self.current_user
        )))

    def post(self):
        url = self.request.get('url')
        file = urllib2.urlopen(url)
        graph = facebook.GraphAPI(self.current_user['access_token'])
        response = graph.put_photo(file, "Test Image")
        photo_url = ("http://www.facebook.com/"
                     "photo.php?fbid={0}".format(response['id']))
        self.redirect(str(photo_url))


class FacebookLogoutHandler(FacebookBaseHandler):
    def get(self):
        if self.current_user is not None:
            self.session['user'] = None

        self.redirect('/')

jinja_environment = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__))
)
#Facebook Classes End


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Register),
                               ('/admin', Admin),
                               ('/admin/tools', Tools),
                               ('/admin/tools/mgmt', Management),
                               ('/admin/tools/admin_reg', Register),
                               ('/admin/tools/event', Event),
                               ('/admin/logout', Logout),
                               ('/admin/facebook/login', FacebookHomeHandler),
                               ('/admin/facebook/logout', FacebookLogoutHandler)
                               ],
                              debug=True,
                              config=config)
