const express			= require('express');
const session			= require('express-session');
const hbs				= require('express-handlebars');
const mongoose			= require('mongoose');
const passport			= require('passport');
const localStrategy		= require('passport-local').Strategy;
const bcrypt			= require('bcrypt');
const app				= express();
const base64url 		= require('base64url');

// 1st party dependencies
var configData = require("./config/connection.js");

// Database
//var connectionInfo = configData.getConnectionInfo();
//console.log (connectionInfo.DATABASE_URL);

mongoose.connect(process.env.DATABASE_URL, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	dbName: process.env.DATABASE_NAME
}); 

const UserSchema = new mongoose.Schema({
	username: {
		type: String,
		required: true
	},
	password: {
		type: String,
		required: true
	},
	token: {
		type: String,
		required: false
	},
	lastLogin: {
		type: Date,
		required: false
	}
});

const User = mongoose.model('User', UserSchema);


// Middleware
app.engine('hbs', hbs({ extname: '.hbs' }));
app.set('view engine', 'hbs');
app.use(express.static(__dirname + '/public'));
app.use(session({
	secret: "verygoodsecret",
	resave: false,
	saveUninitialized: true
}));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Middleware function to always convert username into lowercase to match DB entry
const convertToLowerCase = (req, res, next) => {
	if (req.body.username) {
	  req.body.username = req.body.username.toLowerCase();
	}
	next();
};

// Email validation function
function validateEmail(email) {
	const emailRegex = /^\S+@\S+\.\S+$/;
	return emailRegex.test(email);
}

// Passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});

passport.use(new localStrategy(function (username, password, done) {
	User.findOne({ username: username }, function (err, user) {
		if (err) return done(err);
		if (!user) return done(null, false, { message: 'Incorrect username.' });

		bcrypt.compare(password, user.password, function (err, res) {
			if (err) return done(err);
			if (res === false) return done(null, false, { message: 'Incorrect password.' });
			
			return done(null, user);
		});
	});
}));

function isLoggedIn(req, res, next) {
	if (req.isAuthenticated()) return next();
	res.redirect('/login');
}

function isLoggedOut(req, res, next) {
	if (!req.isAuthenticated()) return next();
	res.redirect('/');
}

// ROUTES
app.get('/', isLoggedIn, (req, res) => {
	res.render("index", { title: "Home" });
});

app.get('/about', (req, res) => {
	res.render("index", { title: "About" });
});

app.get('/login', isLoggedOut, (req, res) => {
	const response = {
		title: "Login",
		error: req.query.error,
		success: req.query.success,
		userexists: req.query.userexists,
		invalidemail: req.query.invalidemail,
		reset: req.query.reset,
		expired: req.query.expired
	}

	res.render('login', response);
});

app.get('/register', isLoggedOut, (req, res) => {
	const response = {
		title: "Register",
		error: req.query.error
	}

	res.render('register', response);
});

app.post('/login', convertToLowerCase, passport.authenticate('local', {	
	successRedirect: '/update-last-login',
	failureRedirect: '/login?error=true'
}));

// After successful login, set the timestamp on the user's lastLogin attribute
app.get('/update-last-login', isLoggedIn, function(req, res) {
	// Update last login time
	User.updateOne(
		{ username: req.user.username },
		{ $set: { lastLogin: new Date() } },
		function(err, result) {
			if (err) {
				console.error(err);
			} else {
				console.log('Last login time updated successfully for', req.user.username);
			}
			res.redirect('/');
		}
	);
});



app.post('/register', async (req, res) => {
	const useremail = req.body.username.toLowerCase();
	const password = req.body.password;

	const exists = await User.exists({ username: useremail });

	if (exists) {
		res.redirect('/login?userexists=true');
		return;
	};

	if (!validateEmail(useremail)) {
		res.redirect('/login?invalidemail=true');
		return;
	};

	bcrypt.genSalt(10, function (err, salt) {
		if (err) return next(err);
		bcrypt.hash(password, salt, function (err, hash) {
			if (err) return next(err);
			
			const newUser = new User({
				username: useremail,
				password: hash,
				token: null,
				lastLogin: new Date() 
			});

			newUser.save();

			res.redirect('/login?success=true');
		});
	});
});

app.get('/logout', function (req, res) {
	req.logout(function(err) {
		if (err) { return next(err); }
		res.redirect('/');
	  });
});

//Route for user to enter email address
app.get('/reset', isLoggedOut, (req, res) => {
	const response = {
		title: "Reset Password",
		error: req.query.error
	}
	res.render('reset', response);
});

app.post('/reset', async (req, res) => {
	const useremail = req.body.username.toLowerCase();
	const user = await User.findOne({username: useremail});
	//const exists = await User.exists({ username: useremail });
	
	// Don't do anything if user doesn't exist
	if (!user) {
		res.redirect('/login?invalidemail=true');
		return;
	};

	// User exists, create a token using the user's attributes and timestamp
	/* Hash contains: 
		- today's date derived from timestamp
		- username
		- lastLogin
		- current password hash

		If any of the above changes, the password reset link shouldn't work
	*/
	const timestamp = new Date();
	// Convert to just today's date without the HH:mm:ss. The token should be valid for only today.
	const date = timestamp.toISOString().split('T')[0]; 
	// Convert lastLogin to milliseconds
	const lastLogin = user.lastLogin.getTime();
	const token = `${date}${user.password}${lastLogin}${user.username}`;
	console.log("Original token: ",token);
	var hashedToken = "";
	

	// Salt and hash the token
	bcrypt.genSalt(10, function (err, salt) {
		if (err) return next(err);
		bcrypt.hash(token, salt, function (err, hash) {
			if (err) return next(err);

			// Convert to a base64url so it doesn't include any slashes
			hashedToken = base64url.fromBase64(hash);

			User.updateOne({username: useremail}, 
				{$set: { token: hashedToken}}, 
				function (err, docs) {
					if (err) {
						console.log(err)
					}
					else {
						console.log('Set token for ', user.username);
						const host = req.headers.host;
						const resetURL = host+"/reset/"+user._id+"/"+hashedToken;
						console.log("Reset URL: ", resetURL);
					}
				}
			);
			res.redirect('/');
		});
	});

	

	// Send email with token to reset password
	
});

// Route for user to enter new password after clicking link
app.get('/reset/:identity/:token', isLoggedOut, async (req, res) => {
	identity = req.params.identity;
	urlSafeToken = req.params.token;

	//Convert from URL-safe hash back to a bcrypt hash
	const token = base64url.toBase64(urlSafeToken);
	console.log("Token from URL: ",token);

	const response = {
		title: "Reset Password",
		error: req.query.error,
		token: req.params.token
	}
	
	const user = await User.findOne({_id: identity});
	// Don't do anything if user doesn't exist
	if (!user) {
		res.redirect('/login?invalidemail=true');
		return;
	};

	// Check if token is still valid by recreating it based on the user's identity
	const timestamp = new Date();
	const date = timestamp.toISOString().split('T')[0]; // convert to just today's date without the HH:mm:ss
	const lastLogin = user.lastLogin.getTime();
	const newtoken = `${date}${user.password}${lastLogin}${user.username}`;
	console.log("New token before hashing: ",newtoken);
	// Compare tokens to see if they match. If they don't, the password reset link should be invalid.
	bcrypt.compare(newtoken, token, function(err, result) {
		console.log(result);
		if (err) return next(err);

		if (result) {
			console.log("Hashes match. Proceeding.");
			res.render('resetpassword', response);
		}

		else {
			// Token is not valid anymore
			res.redirect('/login?expired=true');
		}
	});
	
});

app.post('/resetpassword', isLoggedOut, async (req, res) => {
	const newpass = req.body.password;
	const token = req.body.token; 

	// Validate that there is a single user with that token, then render password reset page
	User.findOne({token: token}, 'username', function (err, user) {
		if (err) {
			res.redirect('/login?invalidemail=true');
		}

		if (user) {
			const username = user.username;
			console.log('Resetting this user password:', username);

			// User exists, salt their new password and update
			bcrypt.genSalt(10, function (err, salt) {
				if (err) return next(err);
				bcrypt.hash(newpass, salt, function (err, hash) {
					if (err) return next(err);
					
					User.updateOne({username: username}, 
						{$set: { password: hash, token: null }}, 
						function (err, docs) {
							if (err) {
								console.log(err)
							}
							else {
								console.log ("Updated Docs: ", docs);
							}
					});
					res.redirect('/login?reset=true');
				});
			});
		}

		else {
			// No user found with this token
			res.redirect('/login?expired=true');
		}
	});
});

app.listen(8080, () => {
	console.log("Listening on port 8080");
});