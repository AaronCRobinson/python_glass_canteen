#!/usr/bin/env python

# import "modules" directory into path
import sys, os
# NOTE: this is where any new modules we are adding to python live
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))
# webserver
from bottle import Bottle, run, request, response, redirect
# templates
import jinja2
from bottle import TEMPLATE_PATH, jinja2_template as template
# for upload function
from google.appengine.ext import blobstore

from User import User, fetch_user
from google.appengine.api import mail

import mimetypes

# Decorator for requiring authentication
def require_session(func, pass_through=True):
	if not pass_through:
		def check_session(*args, **kwargs):
			# NOTE needs to be SSL since secure cookie.
			user = fetch_user( request.get_cookie("username") )
			session_id = request.get_cookie("session", secret=user.cookie_secret)
			if session_id != user.session_id:
				return 'IMPOSTER!!!' # and ask them to login
			return func(*args, **kwargs)
		return check_session
	return func # otherwise return original function
	
# setup app wrapper
app = Bottle()

# update template path
TEMPLATE_PATH.append("./templates")

@app.route('/signup')
def signup():
	return template('signup.html')
	
@app.post('/signup')
def signup_post():
	# check user doesn't already exit
	username = request.forms.get('username')
	email = request.forms.get('email')
	password = request.forms.get('pwd') # is this bad? password now in memory in two places?
	if fetch_user(username):
		# user already exists
		return "user already exists! naughty you!"
		# return error?
	
	#hash, salt = salt_shaker(request.forms.get('pwd'))
	
	# user disable until e-mail verified.
	user = User(name=username, email=email, role="user", disabled=True, password=password)
	
	# send confirmation e-mail (changes user values) and push to database in google cloud
	send_confirmation_email(user)
	#user.put()
	
	return template('confirmation_email.html')

def send_confirmation_email(user):
	# https://developers.google.com/appengine/docs/python/mail/
	confirmation_url = "https://python-glass-canteen.appspot.com/confirmation/" + \
					   "%s/%s:" % (user.name, user.create_confirmation())
	sender_address = "Robinson.Aaron.C@gmail.com"
	user_address = user.email
	subject = "python-glass-canteen: Confirm your registration"
	body = """
Thank you for creating an account! Please confirm your email address by
clicking on the link below:

%s
""" % confirmation_url
    
	mail.send_mail(sender_address, user_address, subject, body)

@app.route('/confirmation/<username>/<secret>')
def confirmation(username, secret):
	user = fetch_user(username)

	if user.check_confirmation(secret):
		user.enable()
		# NOTE: probably not a good idea to set a cookie at this point. (Ask for password again?)
		return template('email_verified.html', name=User.name)
	
	# NOTE: consider other cases?
	return 'WATCHYA DOING HERE!'
	
@app.route('/login')	
def login():
	return template('login.html')

@app.post('/login')
def login_post():
	# TODO: rewrite rewrite rewrite.
	# NOTE: assuming user has an account (TODO: fix this assumption)
	user = fetch_user(request.forms.get('username'))
	#hash = salt_shaker(request.forms.get('pwd'), user.salt)
	
	if user.check_password( request.forms.get('pwd') ):
		# setup a cookie for the user and a session sense they logged in successfully
		session_id, cookie_secret = user.create_new_session()
		response.set_cookie("username", user.name)
		response.set_cookie("session", session_id, secret=cookie_secret, secure=True)
		#user.put() # update user with cookie_sercret and session_id
		return template('success_login.html', name=user.name)
		
	# NOTE: consider adding more cases later. (like request.forms.get('username'))
	return template('failed_login.html', name=user.name)

# NOTE: eventually do something with this?
@app.route('/')
@app.route('/hello/<name>')
def home(name='Stranger'):
	return template('home.html', name=name)
	
@app.route('/upload')
@require_session
def upload():
	return template( 'upload.html', upload_url = blobstore.create_upload_url('/upload') )
	
@app.post('/upload')
@require_session
def upload_post_processing():
	file = request.files.get('file').raw_filename 
	# validate file is image format
	#valid_formats = ['image/x-png', 'image/jpeg', 'image/gif', 'image/bmp']
	if mimetypes.guess_type(file)[0].split('/')[0] != 'image':
		# need to delete blob?
		return "Invalid filetype!"
		#return template( 'upload_error.html')
	
	redirect()
	
@app.post('/upload/<file>')		
def upload_post_html(file):
	#redirect( "/images/" + file )
	return template( 'upload_success.html', filename = file )
 
@app.route('/browse')
def browse_images():
	# this should be temporary. Bad way of doing this (that is passing that object)
	#if mimetypes.guess_type(file).split('/')[0] != 'image':
	#results = blobstore.BlobInfo.gql("WHERE content_type = ")
	return template( 'browse.html', blobstore_results = blobstore.BlobInfo.all())
	
@app.route("/images/<image:re:.+>")
def get_image(image):
	"""
	set header content type. 
	query blobstore, filter on filename, and execute query -> get BlobInfo
	open BlobReader with BlobInfo keyand read data -> return raw data
	"""
	#TODO: consider some kind of validation
	#response.content_type = 'image/jpeg'
	#blob_info = blobstore.BlobInfo.gql("SELECT * FROM BlobInfo WHERE filename = :fname", fname=image)
	blob_info = blobstore.BlobInfo.gql("WHERE filename = :fname", fname=image).get()
	response.content_type = blob_info.content_type
	#blob_info = blobstore.BlobInfo.all().filter('filename',image).get()
	return blobstore.BlobReader(blob_info).read()

@app.error(500)
def error_handler_500():
	return "<html><title> Gotta catch 'em all! </title><body> A Wild ERROR appears! </body></html>"
	
@app.error(404)
def error_handler_404():
	return "<html><title> Gotta catch 'em all! </title><body> A Wild ERROR appears! </body></html>"

run(app=app, server='gae', debug=False)