# Smart-Security-System-ELEC0138-
Web application interface for a smart home security system. This web app allows users to access stored files in cloud storage through a log in system.

The application consists of signup and login pages as well as a profile page which allow the user to access encrypted files stored in AWS S3 cloud storage. The user's information is encrypted and stored in a MongoDB database where it can be used to verify user's identity as well as store keys and passwords for encryption and authentication. The password is hashed using bcrypto and a user's plaintext password is never stored on the server. This allows for the user's files to be stored privately and securely. Files stored on our cloud storage can only be accessed and decrypted by the user after the password has been entered. Additionally, a simply two factor authentication system is in place in order to thoroughly verify the user's identity on login. 

In order to run this file, execute the app.py python file and open the link presented in the console. The server is run locally.
