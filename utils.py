import os
import jinja2
import webapp2
import re
import hmac
import random
import string
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

"""Functions to validate registration inputs with Regex."""
def valid_username(username):
  return re.compile(r"^[a-zA-Z0-9_-]{3,20}$").match(username)

def valid_pass(password):
  return re.compile(r"^.{3,20}$").match(password)

def valid_email(email):
  return re.compile(r"^[\S]+@[\S]+.[\S]+$").match(email)

"""Cookie hashing w/o salt"""
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return '{}|{}'.format(s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
    return False

"""Password Hashing with Salt"""
SECRET = "imsosecret"

def make_salt(length=5):
    return ''.join(random.choice(string.ascii_letters) for x in range(length))

def make_pw_hash(name, pw, salt=None):
    if salt is None:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "{},{}".format(h, salt)

def valid_pw(username, pw, h):
    salt = h.split(',')[1]
    pw_hash = make_pw_hash(username, pw, salt)
    if h == pw_hash:
        return True
    return False

def users_key(group = 'default'):
    return db.Key.from_path('users', group)
