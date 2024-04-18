function verifyNewUser(event) {
    console.log("hello");
    event.preventDefault(); //Prevent form submission

    var firstName = document.getElementById('firstName').value;
    var lastName = document.getElementById('lastName').value;
    var name = firstName.concat(" ", lastName);
    var email = document.getElementById('email');
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    const spawner = require('child_process').spawn;
    
    const userInfo = [firstName, lastName, name, email, username, password];

    console.log('User info: ', userInfo);

    spawner('python', ['../backend/backendmongo.py', JSON.stringify(userInfo)]);

    const pythonProcess = spawner('python', ['../backend/backendmongo.py', JSON.stringify(userInfo)]);

    pythonProcess.stdout.on('data', (data) => {
        console.log('Data recieved: ', data.toString());
    });
}

document.getElementById('Signup').addEventListener('submit', verifyNewUser);



