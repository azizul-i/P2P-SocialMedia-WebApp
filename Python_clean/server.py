import cherrypy
#import ping
#import report
#import broadcast
import Api
import load_new_apikey
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import nacl.pwhash
import nacl.secret
import requests
import time

#import add_pubkey


startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css'/><meta http-equiv='refresh' content='60'> </head><body>"

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
        Page = startHTML + "<h1><center>| Your Secure Social Network |</center></h1><br/>" 
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            #Page += "Account Information:" + "<br/>"
            Page += "<body>What would you like to do today?</body>" + "<br/>"
            Page += "<a href='/api/ping' class = 'ApiApp'>PING</a>" + "<br/>"
            Page += "<a href='/api/list_apis' class = 'ApiApp'>List APIs</a>" + "<br/>"
            Page += "<a href='/api/load_new_apikey' class = 'ApiApp'>Load New API key</a>" + "<br/>"
            Page += "<a href='/api/loginserver_pubkey' class = 'ApiApp'>Load loginserver's public key</a>" + "<br/>"
            Page += "<a href='/api/report' class = 'ApiApp'>REPORT</a>" + "<br/>"
            Page += "<a href='/api/status_report' class = 'ApiApp'>Status REPORT</a>" + "<br/>"
            Page += "<a href='/api/list_users' class = 'ApiApp'>List Online Users</a>" + "<br/>"
            Page += "<a href='/api/get_loginserver_record' class = 'ApiApp'>Load Certificate</a>" + "<br/>"
            Page += "<a href='/api/pubkeys' class = 'ApiApp'>Configure Public Keys</a>" + "<br/>"
            Page += "<a href='/api/config_privdata' class = 'ApiApp'>Configure Private Keys</a>" + "<br/>"
            Page += "<a href='/api/private_message' class = 'ApiApp'>Private Messaging Page</a>"
            #Page += "<body> Status MUST be either 'offline', 'online', 'busy' or 'away' or blank </body>" + "<br/>"
            #Page += '<form action="/api/report" class="ApiApp" method="post" enctype="multipart/form-data">'
            #Page += '<input type="text" name="status"/>'
            #Page += ' <input type="submit" value=" Status Report "/></form>'
            
            Page += '<form action="/api/rx_broadcast" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="message"/>'
            Page += ' <input type="submit" value=" TWEET! "/></form>'
            # REMEMBER TO UNCOMMENT THIS LINE WHEN SERVER IS ONLINE
            #ClientApiApp.rx_broadcast(self)
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('public_key'),cherrypy.session.get('private_key'))
            Api.Api.report_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('status'),cherrypy.session.get('public_key'))
            cherrypy.session['login_record'] = Api.Api.get_loginserver_record_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
            Page += "<a href='/signout'>Sign out</a>"
        except KeyError: #There is no username
            
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML + "<h1><center>| Your Secure Social Network |</center></h1><br/>" 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password : <input type="text" name="password"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose        
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)

    @cherrypy.expose   
    def load_info(self):
        Page = startHTML + "<h1><center>| Your Secure Social Network |</center></h1><br/>" 
        try:
            Page += "Load previous session keys"
            Page += '<form action="/api/get_privatedata" class = "ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="box_password"/>'
            Page += '    <input type="submit" value="RECOVER"/></form>'
            Page += "Generate new session keys" + "<br/>"
            Page += "<a href='/api/add_pubkey' class = 'ApiApp'> Generate Key Pair</a>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except:
            print('txt')
        return Page


        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(self, username, password)
        if error == 0:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            cherrypy.session['status'] = "online"
            #print(cherrypy.session['username'])
            #ping.Login.get_ping(self,cherrypy.session['username'],cherrypy.session['password'])
            #authorised_access.Authenticate.authenticate(self,username,password)
            #broadcast_access.Broadcast.get_key(self,username,password)
            raise cherrypy.HTTPRedirect('/load_info')
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

    @cherrypy.expose
    def return_to_main(self):
        raise cherrypy.HTTPRedirect('/')




       

# Adding a public key endpoint 


def authoriseUserLogin(self,username, password):
    print("Log on attempt from {0}:{1}".format(username, password))

    # REMEMBER TO UNCOMMENT THIS LINE
    response, apikey = Api.Api.load_new_apikey_EP(self,username,password)
    cherrypy.session['api_key'] = apikey
    #response = "ok"
    if response == "ok":
        return 0  
    else:
        print("Failure")
        return 1



class ApiApp(object):

    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }   

    @cherrypy.expose
    def ping(self):
        Page = startHTML  
        Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('public_key'),cherrypy.session.get('private_key'))
        print(cherrypy.session.get('username'))
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>You have successfully Pinged to the sever!</body>" + "<br/>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center> <body> you have failed to Ping </body> </center>"
        return Page   

    @cherrypy.expose
    def report(self, status=None):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        print(status)
        if status == "" or status == None:
            status = "online"
        Api.Api.report_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),status,cherrypy.session.get('public_key'))
        cherrypy.session['status'] = status
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>You have successfully reported to the sever!</body>" + "<br/>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page

    @cherrypy.expose
    def list_apis(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        api_record = Api.Api.list_apis_EP(self)

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>You have successfully listed APIs!!</body>" + "<br/>" + "<br/>"
            for key in api_record.keys():
                Page += str(key) + "<br/>"
                Page += str(api_record[key]) + "<br/>" 
                Page += "<br/>"
            #Page += str(api_record) + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page

    @cherrypy.expose
    def load_new_apikey(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        response, apikey = Api.Api.load_new_apikey_EP(self,cherrypy.session.get('username'),cherrypy.session.get('password'))
        cherrypy.session['api_key'] = apikey
        if response == "ok":
            try:
                Page += "Hello " + cherrypy.session['username'] + "!<br/>"
                Page += "<br/>"
                Page += "<body>You have successfully loaded a new API key!!</body>" + "<br/>" + "<br/>"
                #Page += str(api_record) ry signing in or+ "<br/>"
                Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
            except KeyError: #There is no username
                Page += "<center>Click here to <a href='login'>login</a>.</center>"
        else:
            Page += "Error in identifying user"
        return Page  


    @cherrypy.expose
    def loginserver_pubkey(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        login_record = Api.Api.loginserver_pubkey_EP(self)
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>You have successfully loaded the loginserver public key</body>" + "<br/>" + "<br/>"
            Page += str(login_record) + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page  


    @cherrypy.expose
    def status_report(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body> Update your status in the textbox below!" + "<br/>"
            Page += "<body> Status MUST be either 'offline', 'online', 'busy' or 'away' or blank </body>" + "<br/>"
            Page += '<form action="/api/report" class="ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="status"/>'
            Page += ' <input type="submit" value=" Status Report "/></form>'
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page  
    
    @cherrypy.expose
    def list_users(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        on_usernames, on_connection_address,on_connection_location,on_updated_time,on_publickey,on_status  = Api.Api.list_users_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            for i in range(len(on_usernames)):
                Page += on_usernames[i] + ": Status= " + str(on_status[i]) + "<br/>"
                Page += "<body> Connection Address: </body>" + str(on_connection_address[i])  + "<br/>"
                Page += "<body> Connection Location: </body>" + str(on_connection_location[i])  + "<br/>"
                Page += "<body> Public Key: </body>" + str(on_publickey[i]) + "<br/>"
                Page += "<body> Connection updated at: </body>" + str(on_updated_time[i])  + "<br/>"
                #Page 
                Page += "<br/>"
            Page += "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page 

    @cherrypy.expose
    def get_loginserver_record(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        cherrypy.session['login_record'] = Api.Api.get_loginserver_record_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<p> Your login record has been loaded! </p>" + "<br/>"
            Page += "<br/>"
            #Page += "Login Server Record: " + str(cherrypy.session.get('login_record'))
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page 
    

    @cherrypy.expose
    def pubkeys(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += " Generate Public Key <br/>"

            Page += " Check Public Key  <br/>"
            #Page += "Login Server Record: " + str(cherrypy.session.get('login_record'))
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page 


    @cherrypy.expose
    def get_privatedata(self,box_password=None):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        privkey = Api.Api.decode_privatedata(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),box_password)
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            #Page += privkey + "<br/>"
            cherrypy.session['private_key'] = privkey
            cherrypy.session['public_key'] = Api.Api.generate_pubkey(self,cherrypy.session.get('private_key'))
            Page += "Private Key: "
            Page += cherrypy.session.get('private_key') + "<br/>" 
            Page += "Public Key: "
            Page += cherrypy.session.get('public_key') + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page 


    @cherrypy.expose
    def config_privdata(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += " Add private data <br/>"
            Page += '<form action="/api/add_privatedata" class = "ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="password"/>'
            Page += ' <input type="submit" value=" Save Data "/></form>'
            Page += " Load private data  <br/>"
            Page += '<form action="/api/get_privatedata" class = "ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="box_password"/>'
            Page += ' <input type="submit" value=" Recover private key "/></form>'
            #Page += "Login Server Record: " + str(cherrypy.session.get('login_record'))
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page 


    @cherrypy.expose
    def add_privatedata(self,password=None):
        if (password == None) or (password == ""):
            password = "1234"
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        print(cherrypy.session.get('login_record'))
        Api.Api.add_privatedata(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),
        cherrypy.session.get('login_record'),cherrypy.session.get('private_key'),password)
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page 
        #Page += "<a href='/api/list_users' class = 'ApiApp'>List Online Users</a>"

    @cherrypy.expose
    def add_pubkey(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        cherrypy.session['public_key'],cherrypy.session['private_key'] = Api.Api.add_pubkey_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
        try:
            Page += "Generated new public/private key pair" + "<br/>"
            Page += str(cherrypy.session.get('public_key')) + "<br/>"
            Page += str(cherrypy.session.get('private_key')) + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='login'>login</a>.</center>"
        return Page 

    @cherrypy.expose
    def rx_broadcast(self, message = None):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        Api.Api.rx_broadcast(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('private_key'),cherrypy.session.get('login_record'),message)
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>You have successfully broadcasted to the sever!</body>" + "<br/>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center> <body> you have failed to broadcast </body> </center>"
        return Page


    @cherrypy.expose
    def private_message(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        #Api.Api.rx_broadcast(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('private_key'),cherrypy.session.get('login_record'),message)
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += '<form action="/api/rx_privatemessage" class = "ApiApp" method="post" enctype="multipart/form-data">'
            Page += " Enter target user"
            Page += '    <input type="text" name="t_user"/>' + "<br/>"
            Page += 'Enter targets public key' 
            Page += '    <input type="text" name="t_pubkey"/>' + "<br/>"
            Page += 'Enter message'
            Page += '    <input type="text" name="t_message"/>' + "<br/>"
            Page += '<input type="submit" value=" Send "/></form>'
            #Page += "<body>You have successfully privately messaged </body>" + t_user + "<br/>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center> <body> you have failed to broadcast </body> </center>"
        return Page

    @cherrypy.expose
    def rx_privatemessage(self,t_user=None, t_pubkey=None, t_message=None):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        print(t_user)
        print(t_pubkey)
        print(t_message)
        Api.Api.rx_privatemessage(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('public_key'),cherrypy.session.get('private_key'),cherrypy.session.get('login_record'),t_user,t_pubkey,t_message)
        #Api.Api.rx_broadcast(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('private_key'),cherrypy.session.get('login_record'),message)
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>You have successfully privately messaged </body>" + t_user + "<br/>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center> <body> you have failed to broadcast </body> </center>"
        return Page

class ClientApiApp(object):
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 } 

    @cherrypy.expose
    def rx_broadcast(self):
        received_broadcast = json.loads(cherrypy.request.body.read().decode('utf-8'))
        print(received_broadcast)
        response = {
            "response: ok"
        }
        return json.dumps(response)



    