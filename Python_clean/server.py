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
            
            Page += "<body>What would you like to do today?</body>" + "<br/>"
            Page += "<a href='/api/status_report' class = 'ApiApp'>Change Status</a>" + "<br/>" + "<br/>"



            Page += "<a href='/api/list_users' class = 'ApiApp'>Online Users</a>"
            Page += "   Check who is online, and drop a message"  + "<br/>" + "<br/>"

            Page += "<a href='/config_privdata'>Configure Private Keys</a>" 
            Page += "   Update your private information"
            Page += "<br/>" + "<br/>"

            Page += "<a href='/api/tweeter' class = 'ApiApp'>TWEETER</a>"
            Page += "   Check the latest broadcasts from your peers" + "<br/>" + "<br/>"

            Page += '<form action="/api/tx_broadcast" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="message"/>'
            Page += ' <input type="submit" value=" TWEET! "/></form>' + "<br/>" + "<br/>"
            # REMEMBER TO UNCOMMENT THIS LINE WHEN SERVER IS ONLINE
            #ClientApiApp.rx_broadcast(self)
            ApiApp.list_users(self)
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('public_key'),cherrypy.session.get('private_key'))
            Api.Api.report_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('status'),cherrypy.session.get('public_key'))
            cherrypy.session['login_record'] = Api.Api.get_loginserver_record_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
            Api.Api.tx_ping_check(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
            #ApiApp.tx_ping_check(self)  ################################### CHECK TO MAKE THIS FASTER
            print(cherrypy.session.get('api_key'))
            print("Private Key: " + cherrypy.session.get('private_key'))
            try:
                print("hello")
            except:
                print("#########################################################")
                print("COULD NOT UPDATE DATABASE")
                print("##########################################################")
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
    def load_info(self, error=0):
        Page = startHTML + "<h1><center>| Your Secure Social Network |</center></h1><br/>" 
        if (int(error) >= 0):
            Page += "Invalid Attempt: " + str(cherrypy.session["private_attempt"]) + "<br/>"
            Page += "MAX ATTEMPTS: 3" + "<br/>" + "<br/>"
            if (cherrypy.session["private_attempt"] == 3):
                raise cherrypy.HTTPRedirect('/signout')
                
        try:
            Page += "Enter Unique Password"
            Page += '<form action="/api/get_privatedata" class = "ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="password" name="box_password"/>'
            Page += '    <input type="submit" value="Enter"/></form>'
            #Page += "Forgotten Password" + "<br/>"
            #Page += "<a href='/api/add_pubkey' class = 'ApiApp'> Make New Unique Password</a>" + "<br/>"
            Page += "<center>Click here to <a href='/signout' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
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
            cherrypy.session["private_attempt"] = 0
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

    @cherrypy.expose
    def config_privdata(self):
        try:
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
        except:
            raise cherrypy.HTTPRedirect("/signout")
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += " Change Unique Password <br/>"
            Page += '<form action="/api/add_privatedata" class = "ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="password"/>'
            Page += ' <input type="submit" value=" Save Data "/></form>'
            #Page += " Load private data  <br/>"
            #Page += '<form action="/api/get_privatedata" class = "ApiApp" method="post" enctype="multipart/form-data">'
            #Page += '<input type="text" name="box_password"/>'
            #Page += ' <input type="submit" value=" Recover private key "/></form>'
            #Page += "Login Server Record: " + str(cherrypy.session.get('login_record'))
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
        return Page 
    


       

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
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def checkmessages(self, since=None):
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
        
        response = {
           "response" : "ok",
           "broadcasts": "[..]",
           "private_messages": "[..]",
        }
        response = json.dumps(str(response))
        return response


    def report(self, status=None):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        print(status)
        
        if status == "" or status == None:
            status = "online"
        cherrypy.session["report_response"] = Api.Api.report_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),status,cherrypy.session.get('public_key'))
        if cherrypy.session.get('report_response') == "error":
            print("ERRROR")
            raise cherrypy.HTTPRedirect('/api/status_report')
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
            Page += '<form action="report" class="ApiApp" method="post" enctype="multipart/form-data">'
            Page += '<input type="text" name="status"/>'
            Page += ' <input type="submit" value=" Status Report "/></form>'
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
        return Page  
    
    @cherrypy.expose
    def list_users(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        online_users  = Api.Api.list_users_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))

        data.data.create_database(self)
        total_users = online_users["username"]
 
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
         
            Page += "<br/>"
            for i in range(len(online_users["username"])):
                Page += "<a href = online_user?on_user=" + online_users["username"][i] + ">" + online_users["username"][i] + "</a href>"# + "</br>"
                Page += "</br>"
                Page +="Status = " + str(online_users["status"][i]) + "<br/>"
                #Page += "<body> Connection Address: </body>" + str(on_connection_address[i])  + "<br/>"
                #Page += "<body> Connection Location: </body>" + str(on_connection_location[i])  + "<br/>"
                #Page += "<body> Public Key: </body>" + str(on_publickey[i]) + "<br/>"
                #Page += "<body> Connection updated at: </body>" + str(on_updated_time[i])  + "<br/>"
                #data.data.update_database_users(self,on_usernames[i],on_publickey[i],on_connection_address[i],on_connection_location[i],on_updated_time[i],on_status[i],total_users)
                
                #Page 
                Page += "<br/>"
            print(online_users["username"])
            data.data.update_database_users(self,online_users["username"],online_users["publickey"],online_users["connection_address"],online_users["connection_location"],online_users["connection_updated_at"],online_users["status"],total_users)
            Page += "<br/>"
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            Page += "<center>Click here to <a href='/login'>login</a>.</center>"
        return Page 



    @cherrypy.expose
    def get_privatedata(self,box_password=None):
        #Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        redirect = False
        try:
            print("CHECK")
            privkey,record = Api.Api.decode_privatedata(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),box_password)
            cherrypy.session["private_data"] = record
            print("CHECK")
            cherrypy.session['prev_private_key'] = privkey
            print("CHECK")
            cherrypy.session['box_password'] = box_password
            print("CHECK")
            cherrypy.session['prev_public_key'] = Api.Api.generate_pubkey(self,cherrypy.session.get('prev_private_key'))
            #print(cherrypy.session['public_key'])
            print("CHECK")

            publickey,privatekey = Api.Api.add_pubkey_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
            cherrypy.session['private_key'] = privatekey
            cherrypy.session['public_key'] = publickey
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('public_key'),cherrypy.session.get('private_key'))
            Api.Api.report_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('status'),cherrypy.session.get('public_key'))
            cherrypy.session['login_record'] = Api.Api.get_loginserver_record_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
            Api.Api.add_privatedata(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('login_record'),privatekey,box_password)
            
            redirect = True
            data.data.encrypt_database(self,cherrypy.session.get('username'),cherrypy.session.get('prev_private_key'),cherrypy.session.get('public_key'))
            raise cherrypy.HTTPRedirect("/index")
            #print("FINAL CHECK")
        except:
            if redirect == True:
                raise cherrypy.HTTPRedirect("/index")
            cherrypy.session["private_attempt"]+=1
            raise cherrypy.HTTPRedirect("/load_info?error=" + str(cherrypy.session["private_attempt"]) )






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
    def tweeter(self, username=None, filter_type="none"):
        #conn = sqlite3.connect("secure_database.db")
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        #get the cursor (this is what is used to interact
        print(username)
        print(filter_type)
        #c = conn.cursor()
        #c.execute("SELECT username,publickey,message, sender_created_at from rx_broadcast")
        #rows = c.fetchall()
        broadcasts = data.data.get_broadcasts(self,username,filter_type)
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "<center>TWEETS</center>" + "<br/>"
            Page += "</br>"
            Page += '<form action="/api/filter" class = "ApiApp" method="post" enctype="multipart/form-data">'
            Page += 'Select type'
            Page += '            <input type="radio" name="filter_type" value="username"/> Username' 
            Page += '            <input type="radio" name="filter_type" value="none"/> No Filter'
            Page +="<br/>"
            Page += 'Enter Username'
            Page += '    <input type="text" name="username"/>' + "<br/>"
            Page += '<input type="submit" value=" Filter "/></form>'
            for i in range(len(broadcasts["users"])):
                #print(row[0])
                Page += "User: " + str(broadcasts["users"][i]) + "<br/>"
                #print(row[1])
                Page += "Public Key: " + str(broadcasts["pubkey"][i]) + "<br/>"
                #print(row[2])
                Page += "Tweet: " + str(broadcasts["message"][i]) + "<br/>"
                #print(row[3])
                time = int(broadcasts["timestamp"][i])
                time_str = datetime.datetime.utcfromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')
                Page += "Sent at: " + str(time_str) + "<br/>"
                Page += "<br/>"
                Page += "<br/>"
            #conn.commit()
            #conn.close()
            Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        except KeyError: #There is no username
            
            Page += "<center> <body> you have failed to broadcast </body> </center>"
        return Page
    #return Page


    


    @cherrypy.expose
    def tx_broadcast(self, message = None):
        try:
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
        except:
            raise cherrypy.HTTPRedirect("/signout")
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        #data.data.
        #connection_list = []
        # Implement Network Drop downlist



        connections = data.data.get_connection_address(self)
        for i in range(len(connections["connections"])):
            try:
                Api.Api.rx_broadcast(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('private_key'),cherrypy.session.get('login_record'),message,connections["connections"][i])
                #print(users[i])
            except:
                print(" broadcast Error")
                #print(users[i])
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
           "response" : "ok"
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
    def all_filter(self, bad_word=None):
        Api.Api.add_privatedata(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('login_record'),cherrypy.session.get('private_key'),cherrypy.session.get('box_password'),"none",)



    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_groupinvite(self):
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
        encrypted_groupkey = cherrypy.request.json["encrypted_groupkey"]
        groupkey_hash = cherrypy.request.json["groupkey_hash"]
        timestamp = cherrypy.request.json["sender_created_at"]
        response = {
            "response": "ok",
            "encrypted_groupkey": encrypted_groupkey,
            "sender_created_at" : timestamp,
        }
        response = json.dumps(str(response))
        return response

    @cherrypy.expose
    def tx_groupmessage(self):
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        Api.Api.tx_groupmessage(self,"misl000",cherrypy.session.get('api_key'),cherrypy.session.get('login_record'),cherrypy.session.get('private_key'),"HELLO BABRA","172.23.24.28:10050")
        return Page

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_groupmessage(self):
        loginserver_record = cherrypy.request.json["loginserver_record"]
        group_message = cherrypy.request.json["group_message"]
        groupkey_hash = cherrypy.request.json["groupkey_hash"]
        sender_created_at = cherrypy.request.json["sender_created_at"]
        signature = cherrypy.request.json["signature"]
        

        print("###############################")
        print(loginserver_record)
        print(group_message)
        print(groupkey_hash)
        print(sender_created_at)
        print(signature)
        print("###############################")

        response = {
           "response" : "AZIZUL IS DA BEST"
        }
        response = json.dumps(str(response))
        return response
        


    @cherrypy.expose
    def tx_privatemessage(self, t_message=None):
        #Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        t_user = cherrypy.session.get('target_user')
        t_pubkey = cherrypy.session.get('target_publickey')
        sender_record = data.data.get_user_record(self,t_user)
        print("################################")
        print(t_user)
        print(t_pubkey)
        print(t_message)
        print("################################")
        sent_payload,personal_encrypted_message = Api.Api.rx_privatemessage(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('public_key'),cherrypy.session.get('private_key'),cherrypy.session.get('login_record'),t_user,t_pubkey,t_message,sender_record["user_connection_address"])
        print("CHEEEEEEEEEEEEEECK")
        data.data.update_private_table(self,cherrypy.session.get('username'),sent_payload["target_username"],sent_payload["target_pubkey"],sent_payload["sender_created_at"],personal_encrypted_message,sent_payload["signature"])
        print("ITS IN DA DATABASE")
        raise cherrypy.HTTPRedirect('/api/online_user?on_user=' + t_user)


    
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @cherrypy.expose
    def rx_privatemessage(self):

        print("HAVE U RECIEVED IT !!!!!!")
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
        

        response = {
           "response" : "ok"
        }
        response = json.dumps(str(response))
        return response



    @cherrypy.expose
    def add_friend(self, friend_username=None):
        print(friend_username)
        Api.Api.add_privatedata(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'), cherrypy.session.get('login_record'),cherrypy.session.get('private_key'),cherrypy.session.get('box_password'),friend_username)
        privkeys, records = Api.Api.decode_privatedata(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'),cherrypy.session.get('box_password'))
        print("---------------------------")
        print(records)
        print("----------------------------")
        raise cherrypy.HTTPRedirect('/api/online_user?on_user=' + friend_username + '&friend_added=' + "true")



    @cherrypy.expose
    def display_privatemessage(self,on_user):
        try:
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
        except:
            raise cherrypy.HTTPRedirect("/signout")

        sender,messages,timestamp = data.data.get_private_messages(self,cherrypy.session.get('username'),on_user)
        for i in range(len(sender)):
            print("Sender: " + sender[i])
            #print(sender)
            decrypted_msg = Api.Api.decrypt_private_message(self,cherrypy.session.get('private_key'),messages[i])
            print(decrypted_msg)
            print(timestamp[i])
        return sender,messages,timestamp
            
    @cherrypy.expose
    def online_user(self, on_user=None, friend_added="none"):
        try:
            Api.Api.ping_EP(self,cherrypy.session.get('username'),cherrypy.session.get('api_key'))
        except:
            raise cherrypy.HTTPRedirect("/signout")
        Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        Page += "<center>User: " + on_user + "</center>" + "</br>"
        print("XXXXXXXXXXXXXXXXXXXx")
        print(on_user)
        print("XXXXXXXXXXXXXXXxXXXX")
        Page += "<a href = add_friend?friend_username=" + on_user + ">" + "Add as friend!" + "</a href>" 
        
        if friend_added == "true":
            Page += "</br>"
            Page += "<font color= 'DarkGreen'>Successfully added " + on_user + " as your friend!</font>"
            Page += "</br>"
        else:
            Page+= "</br>"



        try:
            sender,messages,timestamp = data.data.get_private_messages(self,cherrypy.session.get('username'),on_user)
            #last_index = range(len(messages))
            Page += '<div style="height:480px;width:640px;border:1px solid #ccc;font:16px/26px, Serif;overflow:auto;">'
            for i in range(len(messages)):
                try:
                    try:
                        decrypted_msg = Api.Api.decrypt_private_message(self,cherrypy.session.get('prev_private_key'),messages[i])
                    except:
                        decrypted_msg = Api.Api.decrypt_private_message(self,cherrypy.session.get('private_key'),messages[i])
                    Page += "Sender: " + sender[i] + "<br/>"
                    Page += "Message: " + decrypted_msg + "<br/>"
                    time_str = datetime.datetime.utcfromtimestamp(timestamp[i]).strftime('%Y-%m-%d %H:%M:%S')
                    Page += "Sent at: " + time_str + "<br/>"
                    Page += "<br/>"
                except:
                    print("Could not decrypt")


            Page += "</div>"
            Page += "<br/>"
        except: #There is no username
            
            Page += "<center> <body> User is not online! </body> </center>"

        cherrypy.session["target_user"] = on_user
        cherrypy.session["target_publickey"] = data.data.get_pubkey(self,cherrypy.session.get('target_user'))

        Page += '<form action="/api/tx_privatemessage" class = "ApiApp" method="post" enctype="multipart/form-data">'
        Page += 'Enter message'
        Page += '    <input type="text" name="t_message"/>' + "<br/>"
        Page += '<input type="submit" value=" Send "/></form>'
        Page += "<br/>"
        Page += "<center>Click here to <a href='/return_to_main' class = 'MainApp'>RETURN</a>.</center>" + "<br/>"
        
        return Page

    @cherrypy.expose
    def filter(self,username=None, filter_type=None):
        #Page = startHTML + "<h1><center> Your Secure Social Network </center></h1><br/>"
        #Page += username + " " + str(filter_type)
    
        raise cherrypy.HTTPRedirect('/api/tweeter?username=' + username + '&filter_type=' + filter_type)


    

    


    