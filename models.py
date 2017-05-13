import os
import jinja2
import webapp2
import random
import string
from google.appengine.ext import db
from utils import render_str, users_key, make_pw_hash, valid_pw

class BlogPost(db.Model):
    subject = db.StringProperty(required = True)
    author = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateProperty(auto_now = True)

    @classmethod
    def by_id(cls, pid):
        return cls.get_by_id(pid)

    def get_key(self):
        return self.key().id()

    def render_front(self):
        self._id = self.key().id()
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post_front.html", post = self)

    def render_post(self):
        self._id = self.key().id()
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post = self)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        user = cls.all().filter('name =', name).get()
        return user

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and valid_pw(name, pw, user.pw_hash):
            return user

class Likes(db.Model):
    post_id = db.StringProperty(required = True)
    liker_id = db.StringProperty(required = True)

    @classmethod
    def get_like(cls, post_id, liker_id):
        like = cls.all().filter('post_id =', post_id).filter('liker_id =', liker_id).get()
        return like

    @classmethod
    def save(cls, post_id, liker_id):
        post = BlogPost.by_id(int(post_id))
        if post:
            if liker_id != post.author:
                return cls(post_id = post_id,
                        liker_id = liker_id)

class Comment(db.Model):
    post_id = db.StringProperty(required = True)
    commenter_id = db.StringProperty(required = True)
    commenter_name = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateProperty(auto_now = True)

    @classmethod
    def by_post(cls, post_id):
        return Comment.all().filter('post_id =', post_id).order('-created')

    @classmethod
    def register(cls, post_id, commenter_id, content):
        user = User.by_id(int(commenter_id))
        return cls(commenter_name = user.name,
                    post_id = post_id,
                    commenter_id = commenter_id,
                    content = content)
