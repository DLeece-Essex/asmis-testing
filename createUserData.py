#!/usr/bin/env python


import bcrypt, sys, string, random, json
from cryptography.fernet import Fernet

# A basic prep script to make the data needed for the prototype.
# Prompt for each user's input creds, save the output to a text file that can be pasted into the prototype

def newkey():
    # generates a 256bitkey at random and then base64 encodes. Return string and byte array
    thiskey=Fernet.generate_key()
    thiskeystr=thiskey.decode()
    return[thiskey,thiskeystr]


def newpassword(passwdstr):
    salt=bcrypt.gensalt()
    passwdbytes=bytes(passwdstr,'utf-8')
    passwdhash=bcrypt.hashpw(passwdbytes,salt)
    # use decode to convert to string for storage
    passwdhashstr = passwdhash.decode()
    return passwdhashstr

def encryptdata(key,data):
    # Ensure key & data are bytes, not strings
    encryptor=Fernet(key)
    encdata=encryptor.encrypt(data)
    # convert encrypted data to string for storage
    return encdata.decode()

def decryptdata(key,datastr):
    data=bytes(datastr,'utf-8')
    decryptor=Fernet(key)
    clearbytes=decryptor.decrypt(data)
    # return byte array as a string
    return clearbytes.decode()

def newrecord(uname,pwd,contact,role,recdict):
    #tempdict= dict()
    datalist = [pwd,contact,role]
    recdict[uname]=datalist
    return recdict


def testpasswd(pwdstr,pwdhashstr):
    print(pwdhashstr)
    passwdbytes=bytes(pwdstr,'utf-8')
    pwdhash=bytes(pwdhashstr,'utf-8')
    result=bcrypt.checkpw(passwdbytes,pwdhash)

    return result

def tesuserdata(recdict,keylist):
    nextrecord="yes"
    if sys.stdin.isatty():
        while nextrecord:
            print("Checking passwords")
            username = input("Username: ")
            password = input("Password: ")
            pwdhashstr=recdict[username][0]
            if testpasswd(password,pwdhashstr):
                print("the password for {} is {}".format(username,password))
                enccontactstr=recdict[username][1]
                smscontact=decryptdata(keylist[0],enccontactstr)
                print("The SMS contact for {} is {}".format(username,smscontact))
                nextrecord = input("test another account? yes/no")
            else:
                print("that is not the password")
                nextrecord = input("test another password? yes/no")
    return

        

def getuserdata(keylist):
    print("Don't loose this key: ", keylist[1])
    nextrecord="yes"
    recdict=dict()
    if sys.stdin.isatty():
        while nextrecord == "yes":
            print("Follow the prompts to create new user data.")
            username = input("Username: ")
            password = input("Password: ")
            passwordhashstr=newpassword(password)
            smscontact=input("SMS contact number:")
            smscontactbytes=bytes(smscontact,'utf-8')
            enccontact=encryptdata(keylist[0],smscontactbytes)
            rbacrole=input("Role, 1:user,2:mos,3:med,4:it")
            thisrecord=newrecord(username,passwordhashstr,enccontact,rbacrole,recdict)
            print(thisrecord)
            nextrecord = input("Add another record? yes/no")
    return recdict

def storeuserdata(recdict,keylist):
    with open ('user_data.txt','w') as fh:
        json.dump(recdict,fh)
    with open ('user_data.txt','a') as fh:
        fh.write("\n##################################\n")
        fh.write("Encryption Key - do not store with data!\n")
        fh.write("\n" + keylist[1] + "\n" )
    return



    

if __name__ == "__main__":
    keylist=newkey()
    thisrecset=getuserdata(keylist) 
    # Save data to a file
    storeuserdata(thisrecset,keylist)
    tesuserdata(thisrecset,keylist)
