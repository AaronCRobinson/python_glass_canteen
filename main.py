#!/usr/bin/env python

# import "modules" directory into path
import sys, os
# NOTE: this is where any new modules we are adding to python live
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))
# webserver
from bottle import Bottle, run, request, response
# templates
import jinja2
from bottle import TEMPLATE_PATH, jinja2_template as template
# for upload function
from google.appengine.ext import blobstore
# salted passwords
import hashlib

from google.appengine.ext import db
class User(db.Model):
	_role_set = set(["admin","user"])
	name = db.StringProperty(required=True)
	salt = db.StringProperty(required=True)
	hash = db.StringProperty(required=True)
	role = db.StringProperty(required=True, choices=_role_set)
	cake_day = db.DateProperty()
	last_login = db.DateProperty()
	disabled = db.BooleanProperty(indexed=False)
	email = db.StringProperty()

# need to think about salting.
# avoiding uuid module due to adding another package.

# http://stackoverflow.com/questions/9594125/salt-and-hash-a-password-in-python
def salt_shaker(password, salt=None):
	if salt:
		return hashlib.sha512(password + salt).digest()
	else:
		salt = os.urandom(32).encode('hex')
	return hashlib.sha512(password + salt).digest(), salt
	
# setup app wrapper
app = Bottle()

# update template path
TEMPLATE_PATH.append("./templates")

def fetch_user(username):
	# returns user object
	return GqlQuery("SELECT * FROM User WHERE name = :user", user=username).get()

@app.route('/signup')
def signup():
	return template('signup.html')
	
@app.post('/signup')
def singup_post():
	# check user doesn't already exit
	user = request.forms.get('username')
	if fetch_user(user):
		# user already exists
		print "naughty"
		# return error?
	
	hash, salt = salt_shaker(request.forms.get('pwd'))
	
	nu = User(name=new_user, hash=hash, salt=salt)
	nu.put()
	# maybe go to some page saying success?
	return template('home.html', name=request.forms.get('username'))

@app.route('/login')	
def login():
	return template('login.html')

@app.post('/login')
def login_post():
	# assuming user has an account
	salt = fetch_user(request.forms.get('username')).salt
	hash = salt_shaker(request.forms.get('pwd'), salt)
	return template('home.html', name=request.forms.get('username'))

@app.route('/')
@app.route('/hello/:name')
def home(name='Stranger'):
    return template('home.html', name=name)

@app.route('/upload')
def upload():
	return template( 'upload.html', upload_url = blobstore.create_upload_url('/upload') )
		
@app.post('/upload')
def upload_post():
	# NOTE: consider validating the filename...
	# beware of file.filename -> it normalizes names; we like our names weird.
	# consider redirect here
	return template( 'upload.html', filename = request.files.get('file').raw_filename )
 		
@app.route('/browse')
def browse_images():
	# this should be temporary. Bad way of doing this (that is passing that object)
	return template( 'browse.html', blobstore_query = blobstore.BlobInfo.all())
	
@app.route("/images/<image:re:.+>")
def get_image(image):
	"""
	set header content type. 
	query blobstore, filter on filename, and execute query -> get BlobInfo
	open BlobReader with BlobInfo keyand read data -> return raw data
	"""
	#TODO: consider some kind of validation
	response.content_type = 'image/jpeg'
	blob_info = blobstore.BlobInfo.all().filter('filename',image).get()
	return blobstore.BlobReader(blob_info.key()).read()

@app.error(404)
@app.error(500)
def error_handler():
	html = """
	<html>
		<head>
			<title> Error Land </title>
		</head>
		<body>
			Message for you sir <br/>
			From Bottle <br/>
			<embed type="application/x-shockwave-flash" src="http://www.4shared.com/flash/player.swf?ver=9051" style="" quality="high" allowscriptaccess="always" allowfullscreen="false" wmode="opaque" flashvars="file=http://jakesplace.info/droid/media/message_for_you_sir.mp3&amp;volume=50&amp;autoplay=true;play=true;" height="20" width="200" play="true" autplay="true"><br/>
		</body>
	</html>
	"""
	return html

run(app=app, server='gae', debug=False)