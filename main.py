import os
import jinja2
import webapp2
import re
import hmac
import random
import string
import hashlib

from google.appengine.ext import db

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def valid_username(username):
  return USER_RE.match(username)

def valid_pass(password):
  return PASS_RE.match(password)

def valid_email(email):
  return EMAIL_RE.match(email)

## Password Hasing w/o salt
SECRET = "imsosecret"

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return '{}|{}'.format(s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
    return False

## Password Hashing with Salt
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

## Cookie Management
def store_cookie(username, password):
    self.response.headers['Content-Type'] = 'text/plain'
    user_hash = make_secure_val(username)
    pw_hash = make_pw_hash(username, password)
    self.response.headers.add_header('Set-Cookie', 'user=%s' % user_hash)
    # self.response.headers.add_header('Set-Cookie', 'pw_hash=%s' % pw_hash)
    new_account = User(name=username, pw_hash=pw_hash)
    new_account.put()
    self.redirect('/welcome')

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

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
        print "rendering"
        self._id = self.key().id()
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post_front.html", post = self)

    def render_post(self):
        print "rendering"
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


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        params['user_id'] = self.user_id
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def get_user_id(self):
        return self.read_secure_cookie('user_id')

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.get_user_id()
        if uid and User.by_id(int(uid)):
            self.user = User.by_id(int(uid))
            self.user_id = uid
        else:
            self.user = None
            self.user_id = None

class SignUp(Handler):
    def get(self):
        self.render("signup.html", text='')

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.v_password = self.request.get('verify')
        self.email = self.request.get('email')

        usererror = ''
        passerror = ''
        vpasserror = ''
        emailerror = ''

        if self.username:
            u_present = True
            if not valid_username(self.username):
                usererror = "That's not a valid username."
        else:
            usererror = "That's not a valid username."

        if self.password:
            p_present = True
            if not valid_pass(self.password):
                passerror = "That wasn't a valid password."
        else:
            passerror = "That wasn't a valid password."

        if self.v_password:
            vp_present = True
            if not valid_pass(self.v_password):
                vpasserror = "That wasn't a valid verification password."
        else:
            vpasserror = "That wasn't a valid verification password."

        if self.email:
            email_present = True
            if not valid_email(self.email):
                emailerror = "That wasn't a valid email."

        if self.password != self.v_password:
                passerror = "Passwords do not match"

        if usererror == '' and passerror == '' and vpasserror == '' and emailerror == '':
            self.done()
        else:
            self.render("signup.html", username=self.username, usererror=usererror, passerror=passerror, vpasserror=vpasserror, emailerror=emailerror)

        def done(self, *a, **kw):
            raise NotImplementedError

class Register(SignUp):
    def done(self):
        user = User.by_name(self.username)
        if user:
            error = "Username has already been taken"
            self.render('signup.html', usererror=error)

        else:
            user = User.register(self.username, self.password, self.email)
            user.put()
            self.login(user)
            self.redirect('/welcome')


class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render("welcome.html", username=self.user.name)
        else:
            self.redirect('/signup')

class LoginHandler(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/blog')
        else:
            error = "Invalid username or password"
            self.render("login.html", usererror=error)

class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class Blog(Handler):
    def get(self):
        error = self.request.get("error")
        uid = self.get_user_id()
        post_list = list()
        blog_posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC")
        for post in blog_posts:
            post.like = 0
            if len(uid) > 0:
                like = Likes.get_like(str(post.key().id()), uid)
                if like:
                    post.like = 1
            post_list.append(post)

        self.render("blog.html", blog_posts=post_list, error=error)

class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        uid = self.get_user_id()

        if len(uid) > 0:
            if subject and content:
                new_post = BlogPost(subject=subject, content=content, author=uid)
                new_post.put()
                new_id = new_post.key().id()
                self.redirect('/blog/' + str(new_id))
            else:
                error = "Please enter a subject and blog content"
                self.render("newpost.html", error=error)
        else:
            self.redirect("/login")

class BlogPostHandler(Handler):
    def get(self, post_id):
        blog_post = BlogPost.get_by_id(int(post_id))
        uid = self.get_user_id()
        blog_post.like = 0
        if len(uid) > 0:
            like = Likes.get_like(post_id, uid)
            if like:
                blog_post.like = 1

        comments = Comment.by_post(post_id)
        commenting = self.request.get("commenting")
        error = self.request.get("error")
        if blog_post:
            if commenting:
                self.render("permalink.html", post=blog_post, commenting=True, comments=comments, error=error)
            else:
                self.render("permalink.html", post=blog_post, comments=comments, error=error)
        else:
            self.redirect('/blog')

    def post(self, post_id):
        comment = self.request.get("content")
        blog_post = BlogPost.get_by_id(int(post_id))
        uid = self.get_user_id()
        if not comment:
            error = "Error: Please enter a valid comment"
            self.redirect("/blog/"+post_id+"?error="+error)

        elif len(uid) <= 0:
            self.redirect("/login")

        elif self.request.get("new-comment"):
            #Add comment to datastore
            new_comment = Comment.register(post_id, uid, comment)
            new_comment.put()
            self.redirect("/blog/"+post_id)

        elif self.request.get("edit-comment"):
            cur_comment = Comment.get(self.request.get("comment-key"))
            cur_comment.content = comment
            #Validates that commenter and user id is smae
            if uid == cur_comment.commenter_id:
                cur_comment.put()
                self.redirect("/blog/"+post_id)
            else:
                self.error(404)

        elif self.request.get("edit-post"):
            subject = self.request.get("subject")
            if blog_post.author == uid:
                blog_post.subject = subject
                blog_post.content = comment
                blog_post.put()
                self.redirect("/blog/"+post_id)
            else:
                self.error(404)

class CommentDeleteHandler(Handler):
    def get(self, post_id):
        uid = self.get_user_id()
        comment = Comment.get(self.request.get("key"))
        if len(uid) > 0:
            if comment.commenter_id == uid:
                comment.delete()
                self.redirect("/blog/"+post_id)
        else:
            self.redirect("/login")

class PostDeleteHandler(Handler):
    def get(self, post_id):
        uid = self.get_user_id()
        blog_post = BlogPost.get_by_id(int(post_id))
        if len(uid) > 0:
            if blog_post.author == uid:
                blog_post.delete()
                self.redirect("/blog")
                return

            error = "Error: You are not allowed to delete this post!"
            self.redirect("/blog/"+post_id+"?error="+error)
        else:
            self.redirect("/login")

#Redirects user to blog post
class LikesPHandler(Handler):
    def get(self, post_id):
        uid = self.get_user_id()
        if len(uid) > 0:
            if Likes.get_like(post_id, uid):
                error = "Error: You can only like a post once!"
                self.redirect("/blog/"+post_id+"?error="+error)
            else:
                like = Likes.save(post_id, uid)
                if like:
                    like.put()
                    self.redirect("/blog/"+post_id)
                else:
                    error = "Error: You cannot like your own post!"
                    self.redirect("/blog/"+post_id+"?error="+error)
        else:
            self.redirect("/login")

#Redirects user to blog
class LikesBHandler(Handler):
    def get(self, post_id):
        uid = self.get_user_id()
        if len(uid) > 0:
            if Likes.get_like(post_id, uid):
                error = "Error: You can only like a post once!"
                self.redirect("/blog?error="+error)

            else:
                like = Likes.save(post_id, uid)
                if like:
                    like.put()
                    self.redirect("/blog")
                else:
                    error = "Error: You cannot like your own post!"
                    self.redirect("/blog?error="+error)
        else:
            self.redirect("/login")

class UnlikeBHandler(Handler):
    def get(self, post_id):
        uid = self.get_user_id()
        if len(uid) > 0:
            like = Likes.get_like(post_id, uid)
            if like:
                like.delete()
            self.redirect("/blog/"+post_id)
        else:
            self.redirect("/login")

class UnlikePHandler(Handler):
    def get(self, post_id):
        uid = self.get_user_id()
        if len(uid) > 0:
            like = Likes.get_like(post_id, uid)
            if like:
                like.delete()
            self.redirect("/blog")
        else:
            self.redirect("/login")

class MainPage(Handler):
    def get(self):
        self.render("landing.html")

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog', Blog),
    ('/blog/(\d+)', BlogPostHandler),
    ('/like/(\d+)', LikesBHandler),
    ('/unlike/(\d+)', UnlikeBHandler),
    ('/blog/like/(\d+)', LikesPHandler),
    ('/blog/unlike/(\d+)', UnlikePHandler),
    ('/rmcomment/(\d+)', CommentDeleteHandler),
    ('/rmpost/(\d+)', PostDeleteHandler),
    ('/blog/newpost', NewPost),
    ('/signup', Register),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/welcome', WelcomeHandler),
], debug=True)
