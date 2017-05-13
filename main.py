import os
import jinja2
import webapp2
import re
import hmac
import random
import string
import hashlib
from google.appengine.ext import db
from utils import render_str, template_dir, jinja_env, check_secure_val, \
                  make_secure_val, valid_username, valid_pass, valid_email
from models import BlogPost, User, Comment, Likes


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
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
        else:
            self.user = None


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

        if usererror == '' and passerror == '' \
                and vpasserror == '' and emailerror == '':
            self.done()
        else:
            self.render("signup.html", username=self.username,
                        usererror=usererror, passerror=passerror,
                        vpasserror=vpasserror, emailerror=emailerror)

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
        posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC")
        for post in posts:
            post.like = 0
            if len(uid) > 0:
                like = Likes.get_like(str(post.key().id()), uid)
                if like:
                    post.like = 1
            post_list.append(post)

        self.render("blog.html", blog_posts=post_list, error=error)


class NewPost(Handler):
    def get(self):
        if self.get_user_id():
            self.render("newpost.html")
        else:
            self.redirect('/login')

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        uid = self.get_user_id()

        if self.user:
            if subject and content:
                new_post = BlogPost(subject=subject, content=content,
                                    author=uid)
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
        if not self.user:
            return self.redirect('/login')

        comments = Comment.by_post(post_id)
        commenting = self.request.get("commenting")
        error = self.request.get("error")
        uid = self.get_user_id()
        blog_post = BlogPost.get_by_id(int(post_id))
        blog_post.like = 0
        like = Likes.get_like(post_id, uid)

        if like:
            blog_post.like = 1

        if blog_post:
            if commenting:
                self.render("permalink.html", post=blog_post, commenting=True,
                            comments=comments, error=error)
            else:
                self.render("permalink.html", post=blog_post,
                            comments=comments, error=error)
        else:
            self.redirect('/blog')

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        comment = self.request.get("content")
        blog_post = BlogPost.get_by_id(int(post_id))
        uid = self.get_user_id()

        if blog_post is not None:
            if not comment:
                error = "Error: Please enter a valid comment"
                self.redirect("/blog/"+post_id+"?error="+error)

            elif self.request.get("new-comment"):
                self.add_comment(post_id, uid, comment)

            elif self.request.get("edit-comment"):
                self.edit_comment(post_id, comment,
                                  self.request.get("comment-key"))

            elif self.request.get("edit-post"):
                self.edit_post(post_id, blog_post, uid, comment,
                               self.request.get("subject"))

        else:
            self.redirect('/blog')

    def add_comment(self, post_id, uid, comment):
        """Adds comment to datastore."""
        new_comment = Comment.register(post_id, uid, comment)
        new_comment.put()
        self.redirect("/blog/"+post_id)

    def edit_comment(self, post_id, comment_text, comment_key):
        """Validates that commenter = user_id before updating comment."""
        cur_comment = Comment.get(comment_key)
        if cur_comment is not None:
            cur_comment.content = comment_text
            if uid == cur_comment.commenter_id:
                cur_comment.put()
                self.redirect("/blog/"+post_id)
            else:
                self.error(404)
        else:
            self.error(404)

    def edit_post(self, post_id, blog_post, uid, comment, subject):
        """Validates that author = user_id before updating post."""
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


class LikesPHandler(Handler):
    """Saves Like and redirects user to blog post."""
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


class LikesBHandler(Handler):
    """Saves Like and redirects user to blog."""
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
