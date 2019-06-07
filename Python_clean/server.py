import cherrypy
#import ping
#import report
#import broadcast
import datetime
import Api
import data
#import load_new_apikey
#import urllib.request
import sqlite3
import json
import base64
import requests
import nacl.encoding
import nacl.signing
import nacl.pwhash
import nacl.secret
import time
import data

#import add_pubkey


startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css'/><meta http-equiv='refresh' content='60'> </head><body>"

class MainApp(object):
    
	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       



    #cherrypy.session["broadcast_user"] = broadcast_user
    #cherrypy.session["broadcast_"]

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
            Page += "Status: " + cherrypy.session.get('status') + "<br/>"
            
            #Page += "Account Information:" + "<br/>"
            Page += "<body>What would you like to do today?</body>" + "<br/>"
            #Page += "<a href='/api/ping' class = 'ApiApp'>PING</a>" + "<br/>"
            #Page += "<a href='/api/list_apis' class = 'ApiApp'>List APIs</a>" + "<br/>"
            #Page += "<a href='/api/load_new_apikey' class = 'ApiApp'>Load New API key</a>" + "<br/>"
            #Page += "<a href='/api/loginserver_pubkey' class = 'ApiApp'>Load loginserver's public key</a>" + "<br/>"
            #Page += "<a href='/api/report' class = 'ApiApp'>REPORT</a>" + "<br/>"
            Page += "<a href='/api/status_report' class = 'ApiApp'>Change Status</a>" + "<br/>"
            #Page += '<form action="/api/report method="post" enctype="multipart/form-data">'
            #Page += '<input type="button" onclick="online" name="status" value="Go Online">'
            #Page += '<input type="button" onclick="offline" name="status" value="Go Offline">'
            #Page += '<input type="button" onclick="busy" name="status" value="Appear Busy">'    
            #Page += '<input type="button" onclick="away" name="status" value="Appear Away"></form>'
            #Page += 'Password : <input type="password" name="password"/><br/>'
            #Page += '<input type="submit" value="Change"/></form>'


            #Page += '<form action="/api/report" method="post" enctype="multipart/form-data">'
            """Page += '<select name="Status" method="post" enctype="multipart/form-data">'
            Page += '<option value="online">Online</option>'
            Page += '<option value="offline">Offline</option>'
            Page += '<option value="busy">Busy</option>'
            Page += '<option value="away">Away</option>'
            Page += 
            Page += '</select></form>'"""


            Page += "<a href='/api/list_users' class = 'ApiApp'>Online Users</a>"
            Page += "   Check who is online, and drop a message"  + "<br/>"
            #Page += "<a href='/api/get_loginserver_record' class = 'ApiApp'>Load Certificate</a>" + "<br/>"
            #Page += "<a href='/api/pubkeys' class = 'ApiApp'>Configure Public Keys</a>" + "<br/>"
            Page += "<a href='/api/config_privdata' class = 'ApiApp'>Configure Private Keys</a>" 
            Page += "   Update your private information" + "<br/>"
            Page += "<a href='/api/private_message' class = 'ApiApp'>Private Messaging Page</a>" + "<br/>"
            Page += "<a href='/api/tweeter' class = 'ApiApp'>TWEETER</a>"
            Page += "   Check the latest broadcasts from your peers"
            #Page += "<body> Status MUST be either 'offline', 'online', 'busy' or 'away' or blank </body>" + "<br/>"
            #Page += '<form action="/api/report" class="ApiApp" method="post" enctype="multipart/form-data">'
            #Page += '<input type="text" name="status"/>'
            #Page += ' <input type="submit" value=" Status Report "/></form>'
            
            Page += '<form action="/api/tx_broadcast" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="message"/>'
            Page += ' <input type="submit" value=" TWEET! "/></form>'
            # REMEMBER TO UNCOMMENT THIS LINE WHEN SERVER IS ONLINE
            #ClientApiApp.rx_broadcast(self)
            ApiApp.list_users(self)
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('public_key'),cherrypy.session.get('private_key'))
            Api.Api.report_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('status'),cherrypy.session.get('public_key'))
            cherrypy.session['login_record'] = Api.Api.get_loginserver_record_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
            print(cherrypy.session.get('api_key'))
            print("Private Key: " + cherrypy.session.get('private_key'))
            Page += "<a href='/signout'>Sign out</a>"
        except KeyError: #There is no username
            
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML + "<h1><center>| Your Secure Social Network |</center></h1><br/>" 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password : <input type="password" name="password"/><br/>'
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
            Page += "Enter Unique Password"
            Page += '<form action="/api/get_privatedata" class = "ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="box_password"/>'
            Page += '    <input type="submit" value="Enter"/></form>'
            Page += "Forgotten Password" + "<br/>"
            Page += "<a href='/api/add_pubkey' class = 'ApiApp'> Make New Unique Password</a>" + "<br/>"
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
        try:  
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('public_key'),cherrypy.session.get('private_key'))
            response = "You have successfully PINGED to the server!"
        except: 
            response = "User must LOG IN, before being able to PING"
        #if error == "0":
         #   Page += "<body>You have currently do not have a private key!</body>" + "<br/>" + "<br/>"
        #else:
        print(cherrypy.session.get('username'))
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>" + response + "</body>" + "<br/>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center> <body> You must LOG IN before begin able to PING! </body> </center>"
            Page += "<center>Click here to <a href='/login' class = 'MainApp'>login</a> and PING.</center>"

        return Page   

    @cherrypy.expose
    def report(self, status=None):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        print(status)
        
        if status == "" or status == None:
            status = "online"
        """cherrypy.session["report_response"] = Api.Api.report_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),status,cherrypy.session.get('public_key'))
        if cherrypy.session.get('report_response') == "error":
            print("ERRROR")
            raise cherrypy.HTTPRedirect('/api/status_report')"""
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            try:
                Api.Api.report_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),status,cherrypy.session.get('public_key'))
                cherrypy.session["report_response"] = "successful"
            except:
                cherrypy.session["report_response"] = "error"
                raise cherrypy.HTTPRedirect('/api/status_report')
            cherrypy.session['status'] = status
            if status == "offline":
                raise cherrypy.HTTPRedirect('/signout' )
            
            Page += "<br/>"
            Page += "<body>You have successfully reported to the sever!</body>" + "<br/>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center>Click here to <a href='/login' class = 'MainApp'>login</a> and report to other clients.</center>"
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
            
            Page += "<center>Click here to <a href='/login' class = 'MainApp'>login</a> and access list_apis.</center>"
        return Page

    @cherrypy.expose
    def load_new_apikey(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        #response, apikey = Api.Api.load_new_apikey_EP(self,cherrypy.session.get('username'),cherrypy.session.get('password'))
        response = "Invalid API key"

        try: 
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            response, apikey = Api.Api.load_new_apikey_EP(self,cherrypy.session.get('username'),cherrypy.session.get('password'))
            cherrypy.session['api_key'] = apikey
        except KeyError:
            Page += "<center>Click here to <a href='/login' class = 'MainApp'>login</a> and load your apikey.</center>"
    
        if response == "ok":
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>You have successfully loaded a new API key!!</body>" + "<br/>" + "<br/>"
            #Page += str(api_record) ry signing in or+ "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
            return Page
        else:
            #Page += "<body>" + response + "<br/>" + "<br/>"
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
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
        return Page  


    @cherrypy.expose
    def status_report(self, response=None):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            if cherrypy.session.get('report_response') == "error":
                Page += "<font color='blue'>INVALID status!</font>" + "<br/>"
            Page += "<br/>"
            Page += "<body> Update your status in the textbox below!" + "<br/>"
            Page += "<body> Status MUST be either 'offline', 'online', 'busy' or 'away' or blank </body>" + "<br/>"
            Page += '<form action="/api/report" class="ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="status"/>'
            Page += ' <input type="submit" value=" Status Report "/></form>'
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
        return Page  
    
    @cherrypy.expose
    def list_users(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        on_usernames, on_connection_address,on_connection_location,on_updated_time,on_publickey,on_status  = Api.Api.list_users_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))

        data.data.create_database(self)
        total_users = on_usernames
 
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            for i in range(len(on_usernames)):
                Page += on_usernames[i] + ": Status= " + str(on_status[i]) + "<br/>"
                Page += "<body> Connection Address: </body>" + str(on_connection_address[i])  + "<br/>"
                Page += "<body> Connection Location: </body>" + str(on_connection_location[i])  + "<br/>"
                Page += "<body> Public Key: </body>" + str(on_publickey[i]) + "<br/>"
                Page += "<body> Connection updated at: </body>" + str(on_updated_time[i])  + "<br/>"
                #data.data.update_database_users(self,on_usernames[i],on_publickey[i],on_connection_address[i],on_connection_location[i],on_updated_time[i],on_status[i],total_users)
                
                #Page 
                Page += "<br/>"
            data.data.update_database_users(self,on_usernames,on_publickey,on_connection_address,on_connection_location,on_updated_time,on_status,total_users)
            Page += "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
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
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
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
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
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
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
        return Page 


    @cherrypy.expose
    def config_privdata(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"

        ApiApp.display_privatemessage(self)
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
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
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
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
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
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
        return Page 


    @cherrypy.expose
    def tweeter(self):
        conn = sqlite3.connect("database.db")
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        #get the cursor (this is what is used to interact

        c = conn.cursor()
        c.execute("SELECT username,publickey,message, sender_created_at from rx_broadcast")
        rows = c.fetchall()

        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<center>TWEETS</center>" + "<br/>"
            for row in rows:
                print(row[0])
                Page += "User: " + str(row[0]) + "<br/>"
                print(row[1])
                Page += "Public Key: " + str(row[1]) + "<br/>"
                print(row[2])
                Page += "Tweet: " + str(row[2]) + "<br/>"
                print(row[3])
                time = int(row[3])
                time_str = datetime.datetime.utcfromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')
                Page += "Sent at: " + str(time_str) + "<br/>"
                Page += "<br/>"
                Page += "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center> <body> you have failed to broadcast </body> </center>"
        return Page


    


    @cherrypy.expose
    def tx_broadcast(self, message = None):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        #data.data.
        #connection_list = []
        # Implement Network Drop downlist



        users, connection_list = data.data.get_connection_address(self,"1")
        for i in range(len(connection_list)):
            try:
                Api.Api.rx_broadcast(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('private_key'),cherrypy.session.get('login_record'),message,connection_list[i])
                print(users[i])
            except:
                print("Error")
                print(users[i])
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<body>You have successfully broadcasted to the server!</body>" + "<br/>" + "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center> <body> you have failed to broadcast </body> </center>"
        return Page


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        #header_user = cherrypy.request.headers["X-username"]
        try: 
            data.data.create_broadcast_table(self)
        except sqlite3.OperationalError:
            print("Table already created")
        
        header_user = json.dumps(str(cherrypy.request.body.headers.get('X-username')))
        header_apikey =json.dumps(str(cherrypy.request.body.headers.get('X-apikey')))
        #header_apikey = cherrypy.request.headers["X-apikey"]
        print(header_user)
        print(header_apikey)
        try:
            Api.Api.ping_EP(self,header_user,header_apikey,"","")
        except:
            response = "Invalid user"
            return response
        message = cherrypy.request.json["message"]
        loginrecord = cherrypy.request.json["loginserver_record"]
        timestamp = cherrypy.request.json["sender_created_at"]
        info = loginrecord.split(",")
        user_pubkey = info[1]
        user_name = info[0]
        print("user: " + user_name)
        print("public key: " + user_pubkey)
        print("TWEET: " + message)
        #r_header = json.dumps(str(cherrypy.request.body.headers.get('X-username')))
        r_broadcast = json.dumps(cherrypy.request.body.read().decode('utf-8'))
        print(r_broadcast)
        data.data.update_broadcast(self,user_name,user_pubkey,message,timestamp)
        
        response = {
           "response: ok"
        }
        response = json.dumps(str(response))
        return response


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def ping_check(self):
        header_user = json.dumps(str(cherrypy.request.body.headers.get('X-username')))
        header_apikey =json.dumps(str(cherrypy.request.body.headers.get('X-apikey')))
        print(header_user)
        print(header_apikey)
        response = "Invalid Request"
        try:
            Api.Api.ping_EP(self,header_user,header_apikey,"","")
        except:
            response = "Invalid user"
            return response
        connection_address = cherrypy.request.json["connection_address"]
        connection_location = cherrypy.request.json["connection_location"]
        timestamp = cherrypy.request.json["my_time"]
        print(connection_address)
        print(connection_location)
        print(timestamp)
        response = {
           "response: ok"
        }
        response = json.dumps(str(response))
        return response
        

        

    @cherrypy.expose
    def private_message(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        #Api.Api.rx_broadcast(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('private_key'),cherrypy.session.get('login_record'),message)
        try:
            #print(cherrypy.session.get('private_key'))
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += '<form action="/api/tx_privatemessage" class = "ApiApp" method="post" enctype="multipart/form-data">'
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
    def tx_privatemessage(self,t_user=None, t_pubkey=None, t_message=None):
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

    
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @cherrypy.expose
    def rx_privatemessage(self):
        #header_user = cherrypy.request.headers["X-username"]
        """try: 
            data.data.create_broadcast_table(self)
        except sqlite3.OperationalError:
            print("Table already created")"""
        print("PRIVATE KEY: " + str(cherrypy.session.get('private_key')))
        header_user = json.dumps(str(cherrypy.request.body.headers.get('X-username')))
        header_apikey =json.dumps(str(cherrypy.request.body.headers.get('X-apikey')))
        #header_apikey = cherrypy.request.headers["X-apikey"]
        print(header_user)
        print(header_apikey)
        try:
            Api.Api.ping_EP(self,header_user,header_apikey,"","")
        except:
            response = "Invalid user"
            return response
        
        target_pubkey = cherrypy.request.json["target_pubkey"]
        target_username = cherrypy.request.json["target_username"]
        encrypted_message = cherrypy.request.json["encrypted_message"]
        loginrecord = cherrypy.request.json["loginserver_record"]
        timestamp = cherrypy.request.json["sender_created_at"]
        signature_pm = cherrypy.request.json["signature"]
        info = loginrecord.split(",")
        user_pubkey = info[1]
        user_name = info[0]
        print("user: " + user_name)
        print("public key: " + user_pubkey)
        print("target_user: " + target_username)
        print("target_pubkey: " + target_pubkey)
        print("From : " + user_name + " at " + timestamp) 
        print("Message: " + encrypted_message)
        #r_header = json.dumps(str(cherrypy.request.body.headers.get('X-username')))
        body = json.dumps(cherrypy.request.body.read().decode('utf-8'))
        print(body)

        try:
            data.data.create_private_table(self)
        except:
            print("ALREADY CREATED DATABASE")

        #try:
        try:
            print(user_name)
            data.data.update_private_table(self,user_name,target_username,target_pubkey,timestamp,encrypted_message,signature_pm)
        except:
            print("data insert ERROR")
        
        #
        #privkey = requests.Session()
        #privkey = cherrypy.session.get("private_key")
        #print(cherrypy.session.get("private_key"))
        #privkey = (cherrypy.session.get("private_key")) 
        #print("Private Key: ")
        #privkey = Api.Api.decode_privatedata(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),"1234")
        #Api.Api.decrypt_private_message(self,privkey,encrypted_message)

        #
        # data.data.update_broadcast(self,user_name,user_pubkey,message,timestamp)
        #ApiApp.display_privatemessage(self)

        response = {
           "response: ok"
        }
        response = json.dumps(str(response))
        return response
        
    @cherrypy.expose
    def display_privatemessage(self):
        sender,messages,timestamp = data.data.get_private_messages(self,cherrypy.session.get('username'))

        for i in range(len(sender)):
            print("Sender: " + sender[i])
            #print(sender)
            decrypted_msg = Api.Api.decrypt_private_message(self,cherrypy.session.get('private_key'),messages[i])
            print(decrypted_msg)
            print(timestamp[i])
            
        
        
        






class ClientApiApp(object):
    
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 } 

    """ @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_broadcast(self):


        header_user = cherrypy.request.headers["X-username"]
        header_apikey = cherrypy.request.headers["X-apikey"]
        print(header_user)
        print(header_apikey)
        try:
            Api.Api.ping_EP(self,header_user,header_apikey,"","")
        except:
            response = "Invalid user"
            return response
        message = cherrypy.request.json["message"]
        loginrecord = cherrypy.request.json["loginserver_record"]
        print(message)
        info = loginrecord.split(",")
        user_pubkey = info[1]
        user_name = info[0]
        print(user_name)
        print(user_pubkey)
        r_header = json.dumps(str(cherrypy.request.body.headers.get('X-username')))
        r_broadcast = json.loads(cherrypy.request.body.read().decode('utf-8'))

        name = r_header
        record = r_broadcast["loginserver_record"]
        info = record.split(",")
        user_pubkey = info[1]
        #print(info)
        message = r_broadcast["message"]
        timestamp = r_broadcast["sender_created_at"]
        print("RESPONSE RECEIVED!!")

        print("user: " + name)
        #print(record)
        print("user key: " + user_pubkey)
        print("user broadcast: " + message)
        print("timestamp: " + timestamp)
        response = {
            "response: ok"
        }
        response = json.dumps(str(response))
        return response"""



    