import sqlite3

class data(object):
    def create_broadcast_table(self):
        conn = sqlite3.connect("secure_database.db")
        c = conn.cursor()
        c.execute("CREATE TABLE rx_broadcast (username TEXT NOT NULL, publickey TEXT NOT NULL, message TEXT NOT NULL, sender_created_at REAL NOT NULL)")
        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()

    def update_broadcast(self,username,publickey,message,sender_created_at):
        conn = sqlite3.connect("secure_database.db")

        #get the cursor (this is what is used to interact)

        c = conn.cursor()
        #try:
        c.execute("insert into rx_broadcast (username, publickey ,message, sender_created_at) values (?,?,?,?)", (username,publickey,message,sender_created_at))
        #except:
        #    print("Invalid data types/Parameters!")

        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()
    
    def delete_broadcast(self):
        conn = sqlite3.connect("secure_database.db")

        #get the cursor (this is what is used to interact)

        c = conn.cursor()
        #try:
        #c.execute("insert into rx_broadcast (username, publickey ,message, sender_created_at) values (?,?,?,?)", (username,publickey,message,sender_created_at))
        #except:
        #    print("Invalid data types/Parameters!")
        c.execute("delete from rx_broadcast")

        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()
        
    def create_database(self):
        conn = sqlite3.connect("server_database.db")

        #get the cursor (this is what is used to interact)

        c = conn.cursor()
        try:
            c.execute("ALTER TABLE users ADD status text")
            conn.commit()
            response = {
                "response: Table Modified"
            }
            conn.close
        except:
            response = {
                "response: Table already modified"
            }
        conn.close


        print(str(response))
        conn = sqlite3.connect("server_database.db")
        c = conn.cursor()
        #create table
        try:
            c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE, publickey TEXT UNIQUE, connection_address TEXT, connection_location TEXT, connection_updated_at REAL, broadcasts TEXT,messages TEXT)")
        except: 
            response = {
                "reponse: Database created"
            }

        print(str(response))           


        conn.commit()

        #response = {
        #   "response: ok"
        #}

        
        conn.close()

    def update_database_users(self,username,publickey,connection_address,connection_location,connection_updated_at,status,total_users):


        #for i in range(len(total_users)):
         #   if total_users 

            
        #c = conn.cursor()
        
        conn = sqlite3.connect("server_database.db")
        users = []
    #get the cursor (this is what is used to interact)
        c = conn.cursor()

        c.execute("SELECT username from users")
        rows = c.fetchall()
        for row in rows:
            c.execute("UPDATE users SET status = ? WHERE username = ?", ("offline",row[0]))
            
        for row in rows:
            for i in range(len(username)):
                if row[0] == username[i]:
                    c.execute("UPDATE users SET publickey = ? WHERE username = ?", (publickey[i],username[i]))
                    c.execute("UPDATE users SET connection_address = ? WHERE username = ?", (connection_address[i],username[i]))
                    c.execute("UPDATE users SET connection_location = ? WHERE username = ?", (connection_location[i],username[i]))
                    c.execute("UPDATE users SET connection_updated_at = ? WHERE username = ?", (connection_updated_at[i],username[i]))
                    c.execute("UPDATE users SET status = ? WHERE username = ?", (status[i],username[i]))

            
        conn.commit()
        conn.close()


        """ for row in rows:
            #print(username)
            users.append(row[0])
            #print(status)
            if row[0] == username:
                c.execute("UPDATE users SET publickey = ? WHERE username = ?", (publickey,username))
                c.execute("UPDATE users SET connection_address = ? WHERE username = ?", (connection_address,username))
                c.execute("UPDATE users SET connection_location = ? WHERE username = ?", (connection_location,username))
                c.execute("UPDATE users SET connection_updated_at = ? WHERE username = ?", (connection_updated_at,username))
                c.execute("UPDATE users SET status = ? WHERE username = ?", (status,username))
                print(username)
                print(status)

        print(users)"""

        conn = sqlite3.connect("server_database.db")
        #get the cursor (this is what is used to interact)
        c = conn.cursor()
       
        for i in range(len(username)):
            try:
                c.execute("insert into users (username, publickey,connection_address, connection_location, connection_updated_at,status) values (?,?,?,?,?,?)", (username[i],publickey[i],connection_address[i],connection_location[i],connection_updated_at[i],status[i]))
            except: 
                print("ALREADY INSERTED")
        
        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()
    
    def get_connection_address(self):
        conn = sqlite3.connect("server_database.db")
        connections = []
        users = []
        #get the cursor (this is what is used to interact)
        c = conn.cursor()

        c.execute("SELECT username,status,connection_address,connection_location from users")
        rows = c.fetchall()

        """for row in rows:
            if row[1] == "online":
                if connection_location == "0":
                    if row[2] == "0":
                        connections.append(row[2])
                        users.append(row[0])
                elif connection_location == "1":
                    if row[2] == "1":
                        connections.append(row[2])
                        users.append(row[0])
                elif connection_location == "2":
                    if row[2] == "0" or row[2] == "1" or row[2] == "2":
                        connections.append(row[2])
                        users.append(row[0]) 
        """

        for row in rows:
            if row[1] == "online":
                connections.append(row[2])
                users.append(row[0])

        print(connections)

        online_connections = {
            "users": users,
            "connections": connections
        }

        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()

        return online_connections
        #for i in range(len(total_users)):
         #   if total_users 

    def get_all_connections(self):
        conn = sqlite3.connect("server_database.db")
        connections = []
        users = []
        #get the cursor (this is what is used to interact)
        c = conn.cursor()

        c.execute("SELECT username,status,connection_address,connection_location from users")
        rows = c.fetchall()


        for row in rows:
                connections.append(row[2])
                users.append(row[0])

        print(connections)

        all_connections = {
            "users": users,
            "connections": connections
        }

        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()

        return all_connections        

        #except:

    def create_private_table(self):

        #get the cursor (this is what is used to interact)


        conn = sqlite3.connect("server_database.db")
        c = conn.cursor()
        #create table
        try:
            c.execute("CREATE TABLE private_messages (username TEXT NOT NULL, target_user TEXT NOT NULL, target_publickey TEXT, sender_created_at REAL ,messages TEXT, signature_pm TEXT)")
        except: 
            response = {
                "reponse: Database already created"
            }
        


        print(str(response))           


        conn.commit()

        #response = {
        #   "response: ok"
        #}

        
        conn.close()

    def update_private_table(self,sender,t_user,t_pubkey,timestamp,message,signature_pm):
        conn = sqlite3.connect("server_database.db")
        #users = []
        #get the cursor (this is what is used to interact)
        c = conn.cursor()

        #c.execute("SELECT t_user from private_message")
        #print("YOOOOOOOOOOOOOOOOOOOOOOOOOOOZA")
        #rows = c.fetchall()

        #for i in range(len(total_users)):
         #   if total_users


        #try:
        c.execute("insert into private_messages (username, target_user,target_publickey, sender_created_at, messages,signature_pm) values (?,?,?,?,?,?)", (sender,t_user,t_pubkey,timestamp,message,signature_pm))
        #except:     
        print("ALREADY INSERTED")
        
        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()
    
    def get_private_messages(self,user,on_user):
        messages = []
        timestamp = []
        sender = []
        publickey = []
        print(user)


        conn = sqlite3.connect("server_database.db")

        c = conn.cursor()

        c.execute("SELECT target_user,messages,sender_created_at,username,target_publickey FROM PRIVATE_MESSAGES")
        rows = c.fetchall()

        for row in rows:
            if (row[0] == user and row[3] == on_user) or (row[0] == on_user and row[3] == user):
                messages.append(row[1])
                timestamp.append(row[2])
                sender.append(row[3])
                publickey.append(row[4])
        
        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()

        return sender,messages,timestamp
    
    def get_pubkey(self, username):
        conn = sqlite3.connect("server_database.db")
        #get the cursor (this is what is used to interact)
        c = conn.cursor()


        c.execute("SELECT username,publickey from users")
        rows = c.fetchall()
        for row in rows:
            if row[0] == username:
                user_pubkey = row[1]
        
        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()

        return user_pubkey

    def get_user_record(self, username):
        conn = sqlite3.connect("server_database.db")
        #get the cursor (this is what is used to interact)
        c = conn.cursor()
        

        c.execute("SELECT username, publickey,connection_address,connection_location,connection_updated_at,status from users")
        rows = c.fetchall()
        for row in rows:
            if row[0] == username:
                s_username = row[0]
                user_pubkey = row[1]
                user_connection_address = row[2]
                user_connection_location = row[3]
                user_connection_updated_at = row[4]
                user_status = row[5]
        

        
        user_record = {
            "username":s_username,
            "user_pubkey":user_pubkey,
            "user_connection_address":user_connection_address,
            "user_connection_location":user_connection_location,
            "user_connection_updated_at": user_connection_updated_at,
            "user_status": user_status,
        }
        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()

        return user_record

    def get_broadcasts(self,username=None, filter_type=None):
        conn = sqlite3.connect("secure_database.db")
        c = conn.cursor()
        users = []
        pubkey = []
        message = []
        timestamp = []
        c.execute("SELECT username,publickey,message, sender_created_at from rx_broadcast ORDER by sender_created_at DESC")
        rows = c.fetchall()
        print("@@@@@@@@@@@@@@@@@@@@@@@@@@@")
        print(filter_type)
        print(username)
        print('@@@@@@@@@@@@@@@@@@@@@@@@@@')
        for row in rows:
            if filter_type == "username" or filter_type != "none":
                print("IM NOT SUPPPOSE TO BE HERE")
                if row[0] == username:
                    users.append(row[0])
                    pubkey.append(row[1])
                    message.append(row[2])
                    timestamp.append(row[3])
            else:
                print("IM SUPPOSE TO BE HERE")
                users.append(row[0])
                pubkey.append(row[1])
                message.append(row[2])
                timestamp.append(row[3])

        
        broadcasts = {
            "users": users,
            "pubkey": pubkey,
            "message": message,
            "timestamp":timestamp
        }

        print(broadcasts)

        print("UPDATED BROADCASTS")
        conn.commit()
        conn.close()

        return broadcasts







