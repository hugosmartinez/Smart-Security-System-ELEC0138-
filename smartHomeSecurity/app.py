from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from pymongo import collection
from verification import verifyInfo
from bcrypt import gensalt, hashpw
from encryption import generateEncryptionKey, encryptFile, decryptFile
from random import randint
from tfa import sendMessage
import boto3
import os

#Connect to AWS s3 cloud storage
s3 = boto3.client('s3')

#Get connection to mongoDB server
cluster = MongoClient("mongodb+srv://user:smarthomesecurity@smartsecurityusers.fpgnven.mongodb.net/?retryWrites=true&w=majority&appName=smartSecurityUsers")
db = cluster["smartHomeSecurity"]
collection = db["userInfo"]

#Startup Flask
app = Flask(__name__)

#Generate a secret key for Flask to use during a session
flaskSecretKey = os.urandom(24)
app.secret_key = flaskSecretKey

#Set up a limiter to prevent brute force logins
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "150 per hour", "10 per minute"]
)

#Home page
@app.route('/')
def home():
    return render_template('homepage.html')

#Login page
@app.route('/loginPage')
def loginPage():
    return render_template('login.html')

#Verify information provided in login
@app.route('/loginSubmit', methods = ['POST', 'GET'])
def loginCheck():
    error = None
    if request.method == 'POST':
        #Retrieve form info
        username = request.form["username"]
        password = request.form["password"]

        #Query mongoDB and verify
        user = collection.find_one({"username": username})
        #Hash inputted password and compare with stored hashedPassword
        hashInputPw = hashpw(password.encode("utf-8"), user["salt"])
        hashInputPw = hashInputPw.decode("utf-8")

        if user and user["hashedPassword"] == hashInputPw:
            session['user'] = username

            #Store user's encryption key locally to encrypt and decrypt files
            #This key will not be stored when the session ends
            session['encryptionKey'] = generateEncryptionKey(password, user["salt"])

            return redirect(url_for("tfa"))
    error = 'invalid'
    return redirect(url_for('loginPage', errorMsg = error))

#TFA screen
@app.route('/tfa')
def tfa():
    session["otp"] = randint(100000, 999999)
    sendMessage(session["otp"], "email")
    return render_template('tfa.html')

@app.route('/tfaSubmit', methods = ['POST', 'GET'])
def tfaCheck():
    if request.method == "POST":
        response = int(request.form["response"])

        if response == session["otp"]:
            return redirect(url_for("profile"))
    error = "Failed to authenticate"
    return redirect(url_for('loginPage', errorMsg = error))

#User profile
@app.route('/profile')
def profile():
    #Retrieve the list of content associated with the current profile
    contentList = getContentS3('elec0138-storage', session['user'])
    return render_template('profile.html', content = contentList)

def getContentS3(bucket, user):
    response = s3.list_objects_v2(Bucket=bucket)
    print(user)
    content = []
    for obj in response.get('Contents', []):
        #Ensure user is authorized to retrieve the file
        if isAuthorized(user, 'elec0138-storage', obj['Key']):
            content.append(obj['Key'])

    return content

def isAuthorized(user, bucket, objectKey):
    metadata = s3.head_object(Bucket=bucket, Key=objectKey).get('Metadata', {})
    return user == metadata.get('username')

@app.route('/download/<path:contentKey>')
def downloadVideo(contentKey):
    # Download and decrypt file from S3
    encryptedFile = s3.get_object(Bucket='elec0138-storage', Key = contentKey)
    print(encryptedFile)
    decryptedFile = decryptFile(encryptedFile['Body'], session['encryptionKey'])

    # Get file name from metadata
    metadata = s3.head_object(Bucket='elec0138-storage', Key=contentKey).get('Metadata', {})
    fileName = metadata.get('filename')

    return send_file(decryptedFile, as_attachment=True, download_name=fileName)

#Handles file upload
@app.route('/fileUpload', methods = ['POST'])
def fileUpload():
    uploadedFile = request.files["uploadedFile"]
    name = request.form["filename"]
    metadata = {"Metadata": {"username": session['user'], "filename": name}}
    encryptedFile = encryptFile(uploadedFile, session['encryptionKey'])
    return upload(encryptedFile, name, metadata)

def upload(input, name, metadata):
    try:
        print(input, name)
        s3.upload_fileobj(input, 'elec0138-storage', name, metadata)
        return "Successfully uploaded file."
    except Exception as e:
        print(e)
        return "Upload failed."
    
#Signup Page
@app.route('/signup')
def signupPage():
    return render_template('signup.html')

#Verify information provided in signup
@app.route('/signupSubmit', methods = ['POST', 'GET'])
def signupCheck():
    data = [""]
    if request.method == 'POST':
        #Collect data from form
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        #Hash password for storage
        salt = gensalt()
        hashedPassword = hashpw(password.encode("utf-8"), salt)
        #Convert to string for storage
        hashedPassword = hashedPassword.decode("utf-8")

        data = {"firstName": firstName, "lastName": lastName, "email": email, 
                "username": username, "hashedPassword": hashedPassword, "salt": salt}
    res = ""
    if verifyInfo(data):
        res = "signupSuccess"
        collection.insert_one(data)
    else:
        res = "signupFailure"
    return redirect(url_for(res))

@app.route('/signupSuccess')
def signupSuccess():
    return render_template("signupSuccess.html")

@app.route('/signupFailure')
def signupFailure():
    return render_template("signupFailure.html")

if __name__ == '__main__':
    app.run(debug = True)