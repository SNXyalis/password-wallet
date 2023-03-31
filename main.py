from configparser import ConfigParser
import sqlite3

#Global Variables
config_object = ConfigParser()

class Db:
    def __init__(self, db_name="pwd-wallet.db"):
        self.con=sqlite3.connect(db_name)

    def close(self):
        self.con.close()

    def get_users(self):
        cur = self.con.cursor()
        res = cur.execute("SELECT Username FROM Users;")  
        ar = []      
        for elem in res.fetchall():
            username, email, pwd = elem
            ar.append(User(username, email, pwd))
        return ar
    
    def add_user(self, username, email, pwd):
        cur = self.con.cursor()
        cur.execute("INSERT INTO Users VALUES(?, ?, ?)", (username, email, pwd))
        self.con.commit()   

    #TODO
    def add_credential(self):
        None
    
    #TODO
    def get_credentials(self):
        None
    
    #TODO
    def get_credential(self):
        None
    
    def init(self, db_name="create.sql"):
        with open(db_name, 'r') as sql_file:
            sql_script = sql_file.read()
            cur = self.con.cursor()
            cur.executescript(sql_script)
            self.con.commit()
    
    def drop(self, db_name="drop.sql"):
        with open(db_name, 'r') as sql_file:
            sql_script = sql_file.read()
            cur = self.con.cursor()
            cur.executescript(sql_script)
            self.con.commit()


class Credentials:
    def __init__(self, app_name, uid, account_id, pwd, owner_username):
        self.app_name=app_name
        self.uid=uid
        self.account_id=account_id
        self.pwd=pwd
        self.owner=owner_username

class User:
    def __init__(self, username, email, password):
        self.username=username
        self.email=email
        self.password=password

class Session:
    def __init__(self):
        self.session_user = None
        self.session_flag = None

    def save_cookie(self):
        global config_object
        config_object["SESSIONINFO"] = {
            "user": self.session_user.username,
            "email": self.session_user.email,
            "password": self.session_user.password,
            "session_flag": self.session_flag
        }

        with open('config.ini', 'w') as conf:
            config_object.write(conf)

    def read_cookie(self):
        global config_object
        import os
        
        if os.path.exists("config.ini"):
            config_object.read("config.ini")
            userinfo = config_object["SESSIONINFO"]
            self.session_user = User(userinfo["user"],userinfo["email"],userinfo["password"])
            if userinfo["session_flag"] == "True":
                self.session_flag = True
            else:
                self.session_flag = False

    def clear_cookie(self):
        import os
        try:
            if os.path.exists("config.ini"):
                os.remove("config.ini")
        except Exception as e:
            print(e)

    def login(self, username, password):
        username = username 
        password = password 

        db = get_users()
        for elem in db:
            if username==elem.username:
                if password==elem.password:
                    self.session_flag=True
                    self.session_user=User(elem.username, elem.email, elem.password)
                return True
        return False

    def logout(self):
        self.clear_cookie()
        self.session_flag=False
        self.session_user=None
        return self.session_flag

    def is_session_active(self):
        return self.session_flag

    def signin(self, username, email, password):
        username = username 
        email = email 
        password = password 
        db = get_users()
        db.append(User(username, email, password))
        self.session_flag=True
        self.session_user=User(username, email, password)
        return self.session_flag

db = [User("antonis", "example@dot.com", "12345")] #SQLite for this
creds = [] #SQLite for this

def get_users():
    global db
    return db

def get_creds():
    global creds
    return creds

def search_creds(uid):
    creds = get_creds()
    print(creds)
    for i in creds:
        if i.uid == uid:
            return uid
    return None

def main():
    app_status = True
    session = Session()
    try:
        session.read_cookie()
    except Exception as e:
        print(e)
    while(app_status):
        choice = int(input())
        
        #log in
        if choice == 1:
            if session.is_session_active():
                print("You are already logged in")
            else:
                if session.login(input("Enter username: "), input("Password: ")):
                    print("Logged in successfully")
        #log out
        if choice == 2:
            if session.is_session_active:
                if not session.logout():
                    print("Logged out succesfully")
            else:
                print("You are not logged in")

        #sign in
        if choice == 3:
            if session.is_session_active():
                print("You need to log out firstt")
            else:
                if session.signin( input("Enter username: "), input("Email: "), input("Password: ")):
                    print("User created succesfully")
                else:
                    print("Error during sign in")

        #Add creds
        if choice == 4:
            if session.is_session_active():
                cred = Credentials(input("appname"),input("uid"),input("accountid"), input("pwd"), input("owner"))
                get_creds().append(cred)
            else:
                print("Please login")
        
        #Search creds
        if choice == 5: 
            if session.is_session_active:
                searchuid = input("searchuid")
                cred = search_creds(searchuid)
                print(cred)
            else:
                print("Please login")
        
        #Delete creds
        if choice == 6:
            uid = input("uid")
            creds = get_creds()
            for i in range(len(creds)):
                if creds[i].uid == uid:
                    creds.pop(i)
        #Exit
        if choice == -1:
            session.save_cookie()
            #global app_status
            app_status=False

if __name__ == "__main__":
    main()