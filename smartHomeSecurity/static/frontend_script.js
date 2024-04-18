function verifyLogin(event) {
    event.preventDefault(); //Prevent form submission

    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    if (username == 'a' && password == 'b'){
        document.getElementById('loginMessage').textContent = "Success";
        document.getElementById('loginMessage').style.color = 'green';
    }

    else {
        document.getElementById('loginMessage').textContent = "Fail";
        document.getElementById('loginMessage').style.color = 'red';
    }
}

document.getElementById('login').addEventListener('submit', verifyLogin);