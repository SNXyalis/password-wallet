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
            username = elem[0]
            ar.append(username)
        return ar
    
    def add_user(self, username, email, pwd):
        cur = self.con.cursor()
        cur.execute("INSERT INTO Users VALUES(?, ?, ?)", (username, email, pwd))
        self.con.commit() 

    def is_user(self, username, pwd):
        cur = self.con.cursor()
        res = cur.execute("SELECT Username, Pwd from Users WHERE Username=(?) AND Pwd=(?)", (username, pwd)) 
        if res.fetchone() is None:
            return False
        return True

    def add_credential(self, cred):
        cur = self.con.cursor()
        cur.execute("INSERT INTO Credentials VALUES(?, ?, ?, ?, ?)", (cred.app_name, cred.uid, cred.account_id, cred.pwd, cred.owner))
        self.con.commit()
    
    def get_credentials(self, user):
        cur = self.con.cursor()
        res = cur.execute("SELECT App_name, account_id, pwd FROM Credentials WHERE FK_username=(?)", (user.username,))  
        ar = []      
        for elem in res.fetchall():
            ar.append([elem[0], elem[1], elem [2]])
        return ar
    
    def get_credential(self, user, uid):
        cur = self.con.cursor()
        res = cur.execute("SELECT App_name, account_id, pwd FROM Credentials WHERE FK_username=(?) AND User_id=(?)", (user.username, uid))  
        ar = []      
        for elem in res.fetchall():
            ar.append([elem[0], elem[1], elem [2]])
        return ar

    def delete_credential(self, user, uid):
        cur = self.con.cursor()
        cur.execute("DELETE FROM Credentials WHERE FK_username=(?) AND User_id=(?)", (user.username, uid))  
        self.con.commit()
    
    def delete_credentials(self, user):
        cur = self.con.cursor()
        cur.execute("DELETE FROM Credentials WHERE FK_username=(?)", (user.username,))  
        self.con.commit()
    
    def update_credential(self, user, uid, cred):
        cur = self.con.cursor()
        cur.execute("UPDATE Credentials SET  App_name=(?), User_id=(?), Account_id=(?), Pwd=(?), FK_username=(?) WHERE FK_username=(?) AND User_id=(?)", (cred.app_name, cred.uid, cred.account_id, cred.pwd, cred.owner, user.username, uid))  
        self.con.commit()
    
    #TODO
    def backup_db(self):
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

    def assert_credentials(self):
        #TODO check if data is valid
        pass

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

    def login(self, username, password, db):
        username = username 
        password = password 

        if (db.is_user(username, password)):
            self.session_flag=True
            self.session_user=User(username, "none", password)
            return True
        return False

    def logout(self):
        self.clear_cookie()
        self.session_flag=False
        self.session_user=None
        return self.session_flag

    def is_session_active(self):
        return self.session_flag

    def signin(self, username, email, password, db):
        db.add_user(username, email, password)
        self.session_flag=True
        self.session_user=User(username, email, password)
        return self.session_flag

creds = [] #SQLite for this

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
    db = Db()
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
                if session.login(input("Enter username: "), input("Password: "), db):
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
                if session.signin( input("Enter username: "), input("Email: "), input("Password: "), db):
                    print("User created succesfully")
                else:
                    print("Error during sign in")

        #Add creds
        if choice == 4:
            if session.is_session_active():
                cred = Credentials(input("appname"),input("uid"),input("accountid"), input("pwd"), session.session_user.username)
                #assert_credentials()
                db.add_credential(cred)
                #get_creds().append(cred)
            else:
                print("Please login")
        
        #Search creds
        if choice == 5: 
            if session.is_session_active:
                ar = db.get_credentials(session.session_user)
                print(ar)
            else:
                print("Please login")

        #Search creds
        if choice == 10: 
            if session.is_session_active:
                searchuid = input("searchuid")
                ar = db.get_credential(session.session_user, searchuid)
                print(ar)
            else:
                print("Please login")
        
        #Delete cred
        if choice == 6:
            if session.is_session_active():
                searchuid = input("searchuid")
                db.delete_credential(session.session_user, searchuid)
            else:
                print("Please login")
        
        #Delete all creds
        if choice == 9:
            if session.is_session_active():
                db.delete_credentials(session.session_user)
            else:
                print("Please login")
        
        #Update cred
        if choice == 11:
            if session.is_session_active():
                searchuid = input("searchuid")
                cred = Credentials(input("appname"),input("uid"),input("accountid"), input("pwd"), session.session_user.username)
                #assert_credentials()
                db.update_credential(session.session_user, searchuid, cred)
                #get_creds().append(cred)
            else:
                print("Please login")

        if choice == 7:
            db.init()
        if choice == 8:
            db.drop()
        if choice == 88:
            print(db.get_users())
        #Exit
        if choice == -1:
            if session.session_flag:
                session.save_cookie()
            #global app_status
            app_status=False
    db.close()

if __name__ == "__main__":
    main()