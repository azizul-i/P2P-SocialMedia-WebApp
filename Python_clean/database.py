import sqlite3


conn = sqlite3.connect("secure_db.db")

#get the cursor (this is what is used to interact)

c = conn.cursor()

#create table

c.execute("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE, publickey TEXT UNIQUE, connection_address TEXT UNIQUE, connection_location TEXT, connection_updated_at TEXT, broadcasts TEXT,messages TEXT)")


#c.execute("""insert into broadcastv2
#             (username,message,created_at) 
#             values 
#             ("misl000","Hello adidul", 1234)""")


#c.execute("SELECT username,message,created_at from broadcastv2")
#rows = c.fetchall()
#for row in rows:
#    print(row[0])


#names = {}
#for row in rows:
#    names[row[0]] = [int(code) for code in row[1].split(',')]
#    print(names)

conn.commit()

response = {
    "response: ok"
}

print(str(response))
conn.close()