CREATE TABLE Users (
    Username varchar(256) NOT NULL PRIMARY KEY,
    Email varchar(256) NOT NULL,
    Pwd varchar(256) NOT NULL
);

CREATE TABLE Credentials (
    App_name varchar(256) NOT NULL, 
    User_id int NOT NULL, 
    Account_id varchar(256) NOT NULL, 
    Pwd varchar(256) NOT NULL, 
    FK_username varchar(256) NOT NULL FOREIGN KEY REFERENCES Users(Username)
);