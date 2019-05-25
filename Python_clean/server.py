import cherrypy
#import ping
#import add_pubkey


startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>" 
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Account Information:" + "<br/>"
            Page += "<body>What would you like to do today?</body>" + "<br/>"
            Page += '<form action="/add_publickey" method="post" enctype="multipart/form-data">'
            Page += '<input type="submit" value="Add Public Key"/></form>' + "<br/>"
            Page += '<a href="add_publickey"><button>Generate Public Key</button></a>'
            Page += "<a href='/signout'>Sign out</a>"
        except KeyError: #There is no username
            
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(self, username, password)
        if error == 0:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            #ping.Login.get_ping(self,cherrypy.session['username'],cherrypy.session['password'])
            #authorised_access.Authenticate.authenticate(self,username,password)
            #broadcast_access.Broadcast.get_key(self,username,password)
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###

# Adding a public key endpoint
@cherrypy.expose
def add_publickey(self,username=None,password=None):
    error = authoriseUserLogin(self, cherrypy.session['username'], cherrypy.session['password'])
    if error == 0:
        raise cherrypy.HTTPRedirect('/')
    else:
        raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

def authoriseUserLogin(self,username, password):
    print("Log on attempt from {0}:{1}".format(username, password))
    if (username.lower() == "user") and (password.lower() == "password"):
        print("Success")
        return 0
    elif (username.lower() == "misl000") and (password.lower() == "misl000_171902940"):
        print("Success")
        #ping.Login.get_ping(self,username,password)
        return 0  
    else:
        print("Failure")
        return 1