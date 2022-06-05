const passport=require('passport');
const LocalStrategy=require('passport-local').Strategy;
const express = require('express');
const app = express();
const bodyParser = require("body-parser");
const mysql = require('mysql');
const crypto=require('crypto');
var session = require('express-session');
var MySQLStore = require('express-mysql-session')(session);


// ===== MySQL Session ===== //

app.use(session({
	key: 'session_cookie_name',
	secret: 'session_cookie_secret',
	store: new MySQLStore({
        host:'localhost',
        port:3306,
        user:'root',
        password: "",
        database:'cookie_user'
    }),
	resave: false,
    saveUninitialized: false,
    cookie:{
        maxAge:1000*60*60*24,
    }
}));


app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static('public'));
app.set("view engine", "ejs");



// ===== Database ===== //
var con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: ""
});

var sql = "CREATE TABLE IF NOT EXISTS `NodePractice`.`users` (`id` int(11) NOT NULL AUTO_INCREMENT, `firstName` varchar(120) NOT NULL, `lastName` varchar(120) NOT NULL, `address` varchar(200) NOT NULL, `postCode` varchar(200) NOT NULL, `phoneNumber` varchar(200) NOT NULL, `email` varchar(200) NOT NULL, `userName` varchar(200) NOT NULL, `password` varchar(200) NOT NULL, `hash` varchar(200) NOT NULL, `salt` varchar(200) NOT NULL, `isAdmin` varchar(200) NOT NULL, PRIMARY KEY (`id`), UNIQUE KEY `phoneNumber` (`phoneNumber`), UNIQUE KEY `email` (`email`))";

con.connect(function(err) {
    if (err) throw err;
    con.query("CREATE DATABASE IF NOT EXISTS NodePractice;", function (err, result) {
        if (err) throw err;
        //console.log("Database NodePractice created");
    });

    con.query(sql, function (err, result) {
        if(err) throw err;
    });

    con.query("CREATE DATABASE IF NOT EXISTS cookie_user;", function (err, result) {
        if (err) throw err;
        //console.log("Database cookie_user created");
    });    
});



const customFields = {
    usernameField:'userName',
    passwordField:'password',
};

// ===== PassportJS ===== //
const verifyCallback = (userName, password, done) => {
    con.query('SELECT * FROM `NodePractice`.`users` WHERE userName = ? ', [userName], function(error, results, fields) {
        if (error) 
            return done(error);

        if(results.length == 0) {
            return done(null,false);
        }
        const isValid = validPassword(password, results[0].hash, results[0].salt);
        user = {id:results[0].id, email:results[0].username, hash:results[0].hash, salt:results[0].salt};

        if(isValid) {
            return done(null,user);
        } 
        else {
            return done(null,false);
        }
    });
}

const strategy = new LocalStrategy(customFields, verifyCallback);
passport.use(strategy);

passport.serializeUser((user, done) => {
    //console.log("inside serialize");
    done(null, user.id)
});

passport.deserializeUser(function(userId, done) {
    //console.log('deserializeUser' + userId);
    con.query('SELECT * FROM `NodePractice`.`users` WHERE id = ?',[userId], function(error, results) {
        done(null, results[0]);    
    });
});



// ===== Middleware ===== //
function validPassword(password, hash, salt) {
    var hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 60, 'sha512').toString('hex');
    return hash === hashVerify;
}

function generatePassword(password) {
    var salt = crypto.randomBytes(32).toString('hex');
    var genhash = crypto.pbkdf2Sync(password, salt, 10000, 60, 'sha512').toString('hex');
    return {salt: salt, hash: genhash};
}

function isAuth(req, res, next) {
    if(req.isAuthenticated()) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req, res, next) {
    if(req.isAuthenticated() && req.user.isAdmin == 1) {
        next();
    }
    else {
        res.redirect('/notAuthorizedAdmin');
    }   
}

function userExists(req, res, next) {
    con.query('SELECT * FROM `NodePractice`.`users` WHERE userName = ? ', [req.body.userName], function(error, results, fields) {
        if (error) {
            //console.log("Error");
        }
        else if(results.length>0)
            res.redirect('/userAlreadyExists')
        else
            next();
    });
}


app.use((req, res, next) => {
    next();
});

// ===== Routes ===== //
app.get('/', (req, res, next) => {
    //res.send(req.user.userName)
    if(req.isAuthenticated())
        res.redirect('/success')
    else
        res.render('login')
});

app.get('/login', (req, res, next) => {
    if(req.isAuthenticated())
        res.redirect('/success')
    else
        res.render('login')
});

app.get('/logout', (req, res, next) => {
    req.logout(); //Delete from sheeeshion
    res.redirect('/success');
});

app.get('/login-success', (req, res, next) => {
    res.send('<p>You successfully logged in. --> <a href="/success">Go to protected route</a></p>');
});

app.get('/login-failure', (req, res, next) => {
    res.send('You entered the wrong password.');
});

app.get('/viewUsers', (req, res, next) => {
    //console.log("Nakapasok");
    if(!req.isAuthenticated())
        res.redirect('/login')
    else {
        con.query('SELECT firstName, lastName, address, postCode, phoneNumber, email, userName FROM `NodePractice`.`users`', function(error, results, fields) {
            if (error) {
                console.log("Error");
            }
            console.log(results)
            
            //var results = JSON.stringify(results)
            var resultsCount  = Object.keys(results).length
            res.render('viewUsers', {results: results, resultsCount: resultsCount})
        });
    }
});

app.get('/addUser', (req, res, next) => {
    //console.log("Nakapasok");
    if(!req.isAuthenticated())
        res.redirect('/success')
    else
        res.render('addUser')
});

app.post('/addUser', userExists, (req, res, next) => {
    if(!req.isAuthenticated())
        res.redirect('/success')
    else {
        //console.log("Test" + req.body.password);
        const saltHash = generatePassword(req.body.password);
        //console.log("Test" + saltHash);
        const salt = saltHash.salt;
        const hash = saltHash.hash;

        con.query('INSERT INTO `NodePractice`.`users` (firstName, lastName, address, postCode, phoneNumber, email, userName, password, hash, salt, isAdmin) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0) ', [req.body.firstName, req.body.lastName, req.body.address, req.body.postCode, req.body.phoneNumber, req.body.email, req.body.userName, req.body.password, hash, salt], function(error, results, fields) {
            if (error) {
                //console.log("Error");
            }
        });
        res.redirect('/viewUsers');
    }
});

// Edit User
app.get('/editUser/:userName', (req, res, next) => {
    //console.log("Nakapasok");
    if(!req.isAuthenticated())
        res.redirect('/login')
    else {
        con.query('SELECT * FROM `NodePractice`.`users` WHERE userName = ? ', [req.params.userName], function(error, results, fields) {
            if (error) {
                //console.log("Error");
            }
            //console.log(results)
            res.render('editUser', {
                firstNameValue: results[0].firstName,
                lastNameValue: results[0].lastName,
                addressValue: results[0].address,
                postCodeValue: results[0].postCode,
                phoneNumberValue: results[0].phoneNumber,
                emailValue: results[0].email,
                userNameValue: results[0].userName,
                passwordValue: results[0].password
            })
        });
    }
});

app.post('/editUser/:userName', (req, res, next) => {
    if(!req.isAuthenticated())
        res.redirect('/login')

    else {
        //console.log("Test" + req.body.password);
        const saltHash = generatePassword(req.body.password);
        //console.log("Test" + saltHash);
        const salt = saltHash.salt;
        const hash = saltHash.hash;
        con.query("UPDATE `NodePractice`.`users` SET firstName = ?, lastName = ?, address = ?, postCode = ?, phoneNumber = ?, email = ?, userName = ?, password = ?, salt = ?, hash = ? WHERE userName = ? ", [req.body.firstName, req.body.lastName, req.body.address, req.body.postCode, req.body.phoneNumber, req.body.email, req.body.userName, req.body.password, salt, hash, req.params.userName], function(error, results, fields) {
            if (error) {
                console.log(error);
            }
        });
        res.redirect('/login');
    }
});

// Delete User
app.post('/deleteUser/:userName', (req, res, next) => {
    if(!req.isAuthenticated())
        res.redirect('/login')
    else {
        con.query("DELETE FROM `NodePractice`.`users` WHERE userName = ? ", [req.params.userName], function(error, results, fields) {
            if (error) {
                console.log(error);
            }
        });
        res.redirect('/viewUsers');
    }
});

app.post('/login', passport.authenticate('local', {failureRedirect:'/login-failure', successRedirect:'/success'}));

app.get('/success', isAuth, (req, res, next) => {
    //console.log("Nakapasok");
    res.render('success')
});

app.get('/admin-route', isAdmin,(req, res, next) => {
    //console.log("Nakapasok");
    res.send('<h1 class="font text_pad">You are admin</h1><p><a href="/logout">Logout and reload</a></p>');
});

app.get('/notAuthorized', (req, res, next) => {
    //console.log("Nakapasok");
    res.send('<h1 class="font text_pad">You are not authorized to view the resource </h1><p><a href="/login">Retry Login</a></p>');
});

app.get('/notAuthorizedAdmin', (req, res, next) => {
    //console.log("Nakapasok");
    res.send('<h1 class="font text_pad">You are not authorized to view the resource as you are not the admin of the page  </h1><p><a href="/login">Retry to Login as admin</a></p>');
});

app.get('/userAlreadyExists', (req, res, next) => {
    //console.log("Nakapasok");
    res.send('<h1>Sorry, this username is taken </h1><p><a href="/addUser">Register with different username</a></p>');
});

app.listen(3000, function() {
    console.log('Listening on port 3000')
});
