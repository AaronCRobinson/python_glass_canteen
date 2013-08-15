import os , hashlib						# salted passwords
from google.appengine.ext import db		# GAE for dbs

# NOTE: need to figure out where/how this needs to go
def fetch_user(username):
	# returns user object
	return db.GqlQuery("SELECT * FROM User WHERE name = :user", user=username).get()

# On hashing -- http://stackoverflow.com/questions/9594125/salt-and-hash-a-password-in-python
class User(db.Model):
	_role_set = set(["admin","user"])
	name = db.StringProperty(required=True)
	salt = db.StringProperty(required=True)
	hash = db.StringProperty(required=True)
	session_id = db.StringProperty()
	cookie_secret = db.StringProperty()
	role = db.StringProperty(required=True, choices=_role_set)
	last_login = db.DateProperty()
	disabled = db.BooleanProperty(indexed=False)
	email = db.StringProperty()
	
	def __init__(self, *args, **kwargs):
		if 'password' in kwargs: 
			kwargs['hash'], kwargs['salt'] = self._create_hash( kwargs['password'] )
		super(User, self).__init__(*args, **kwargs)
		if 'password' in kwargs: self.put() # Then we know this is a new user.
			
	def _create_hash(self, password):
		salt = os.urandom(32).encode('hex')
		hash = hashlib.sha512(password + salt).hexdigest()
		return hash, salt
	
	def create_new_session(self): # stored inside cookie
		# NOTE: session id could probably be md5?
		self.session_id = hashlib.sha512( os.urandom(32).encode('hex') ).hexdigest()
		self.cookie_secret = hashlib.sha512( os.urandom(32).encode('hex') ).hexdigest()
		self.put()
		return self.session_id, self.cookie_secret
	
	def create_confirmation(self):
		# We are going to use cookie_secret because 
		# it won't have a value till after confirmation
		self.cookie_secret = hashlib.md5().hexdigest()
		self.put()
		return self.cookie_secret
		
	def check_confirmation(self, secret):
		return self.cookie_secret == secret
		
	def check_password(self, password):
		# NOTE: this is more like a "check_auth"...
		hash = hashlib.sha512(password + self.salt).hexdigest()
		if self.disabled == False and self.hash == hash:
			return True
		return False
		
	def enable(self):
		self.disabled = False
		self.put()
		return
