import sqlite3

class data(object):
    def create_broadcast_table(self):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("CREATE TABLE rx_broadcast (username TEXT NOT NULL, publickey TEXT NOT NULL, message TEXT NOT NULL, sender_created_at REAL NOT NULL)")
        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()

    def update_broadcast(self,username,publickey,message,sender_created_at):
        conn = sqlite3.connect("database.db")

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
        conn = sqlite3.connect("database.db")

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
        conn = sqlite3.connect("server_database.db")
        users = []
        #get the cursor (this is what is used to interact)
        c = conn.cursor()

        c.execute("SELECT username from users")
        print("YOOOOOOOOOOOOOOOOOOOOOOOOOOOZA")
        rows = c.fetchall()

        #for i in range(len(total_users)):
         #   if total_users 

            
        c = conn.cursor()

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



        try:
            c.execute("insert into users (username, publickey,connection_address, connection_location, connection_updated_at,status) values (?,?,?,?,?,?)", (username,publickey,connection_address,connection_location,connection_updated_at,status))
        except: 
            print("ALREADY INSERTED")
        
        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()
    
    def get_connection_address(self,connection_location):
        conn = sqlite3.connect("server_database.db")
        connections = []
        users = []
        #get the cursor (this is what is used to interact)
        c = conn.cursor()

        c.execute("SELECT username,status,connection_address,connection_location from users")
        rows = c.fetchall()

        for row in rows:
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
        
        print(connections)

        conn.commit()

        response = {
            "response: ok"
        }

        print(str(response))
        conn.close()

        return users,connections
        #for i in range(len(total_users)):
         #   if total_users 

            

        #except:

    def create_private_table(self):

        #get the cursor (this is what is used to interact)


        conn = sqlite3.connect("server_database.db")
        c = conn.cursor()
        #create table
        try:
            c.execute("CREATE TABLE private_message (username TEXT NOT NULL, target_publickey TEXT, connection_updated_at REAL ,messages TEXT, signature_pm)")
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


