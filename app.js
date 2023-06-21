const express			= require('express');
const session			= require('express-session');
const hbs				= require('express-handlebars');
const mongoose			= require('mongoose');
const passport			= require('passport');
const localStrategy		= require('passport-local').Strategy;
const bcrypt			= require('bcrypt');
const app				= express();
const base64url 		= require('base64url');
const crypto			= require('crypto');
const axios 			= require('axios');

// 1st party dependencies
var configData = require("./config/connection.js");
var mailer = require("./config/sendmail.js");
var recaptcha = require("./config/recaptcha.js");

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
	},
	usernamehash: {
		type: String,
		required: false
	}
});

const User = mongoose.model('User', UserSchema);


// Middleware
app.engine('hbs', hbs({ extname: '.hbs' }));
app.set('view engine', 'hbs');
app.use(express.static(__dirname + '/public'));
app.use(session({
	secret: process.env.SESSION_SECRET, // Any random hash will do
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

// Middleware function to convert a value to a SHA-256 hash
function sha256Hash(value) {
	const hash = crypto.createHash('sha256');
	hash.update(value);
	return hash.digest('hex');
}

// Middleware function to validate an email address against regex
function validateEmail(email) {
	const emailRegex = /^\S+@\S+\.\S+$/;
	return emailRegex.test(email);
}

// Middleware function to validate a password against complexity requirements
function validatePasswordStrength(password) {
	const complexityRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
	return complexityRegex.test(password);
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
	res.render("index", { title: "Home", user: req.user._doc});
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
		expired: req.query.expired,
		resetsuccess: req.query.resetsuccess
	}
	res.render('login', response);
});

app.get('/register', isLoggedOut, (req, res) => {
	const response = {
		title: "Register",
		hash: process.env.SESSION_SECRET
	}

	res.render('register', response);
});

app.post('/login', convertToLowerCase, recaptcha.recaptchaVerification, passport.authenticate('local', {	
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



app.post('/register', recaptcha.recaptchaVerification, async (req, res) => {
	const useremail = req.body.username.toLowerCase();
	const password = req.body.password;

	if (!validateEmail(useremail)) {
		res.render('register', {customerror: "Invalid Email Address"});
		return;
	};

	if (!validatePasswordStrength(password)) {
		res.render('register', {customerror: "Password must be 8+ characters, contain at least 1 capital letter, 1 lowercase letter, and a number."});
		return;
	};
	
	// Proceed with registration
	const exists = await User.exists({ username: useremail });

	if (exists) {
		res.render('login', {customerror: "This account already exists. Please log in instead."});
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
				lastLogin: new Date(),
				usernamehash: sha256Hash(useremail)
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
	
	// Don't do anything if user doesn't exist
	if (!user) {
		res.redirect('/login?resetsuccess=true');
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
	//console.log("Original token: ",token);
	const SHA256token = sha256Hash(token);
	var hashedUsername = user.usernamehash;

	// Set the token on the user
	User.updateOne({username: useremail}, 
		{$set: { token: SHA256token}}, 
		function (err, docs) {
			if (err) {
				console.log(err)
			}
			else {
				console.log('Set password reset token for ', user.username);
				const host = req.headers.host;
				const resetURL = "https://"+host+"/reset/"+hashedUsername+"/"+SHA256token;
				console.log("Reset URL: ", resetURL);

				mailer.sendEmail({ 
					from: "SimpleWave <noreply@dev.simplewave.ca>", 
					to: useremail, 
					subject: "SimpleWave Password Reset", 
					html: "Here is your link to reset your password: " + resetURL
				});
			}
		}
	);
	res.redirect('/login?resetsuccess=true');
});

// Route for user to enter new password after clicking link
app.get('/reset/:identity/:token', isLoggedOut, async (req, res) => {
	const identity = req.params.identity;
	const token = req.params.token;
	//console.log("Token from URL: ",token," and identity: ", identity);

	const response = {
		title: "Reset Password",
		error: req.query.error,
		token: token
	}
	
	const user = await User.findOne({usernamehash: identity});
	// Don't do anything if user doesn't exist
	if (!user) {
		console.log ("User not found - user hash doesn't match any user.");
		res.redirect('/login?expired=true');
		return;
	};

	// Check if token is still valid by recreating it based on the user's identity
	const timestamp = new Date();
	const date = timestamp.toISOString().split('T')[0]; // convert to just today's date without the HH:mm:ss
	const lastLogin = user.lastLogin.getTime();
	const newtoken = `${date}${user.password}${lastLogin}${user.username}`;
	//console.log("New token before hashing: ",newtoken);
	const SHA256newtoken = sha256Hash(newtoken);
	console.log("Freshly hashed token to compare with token passed in URL: ",SHA256newtoken);
	
	if (SHA256newtoken == token) {
		console.log("Hashes match. Proceeding to let user reset password.");
		res.render('resetpassword', response);
	}

	else {
		// Token is not valid anymore
		console.log("Hashes don't match. Token is no longer valid.");
		res.redirect('/login?expired=true');
	}
	
});

app.post('/resetpassword', isLoggedOut, async (req, res) => {
	const newpass = req.body.password;
	const token = req.body.token; 

	// Validate password commplexity
	if (!validatePasswordStrength(newpass)) {
		res.render('resetpassword', {customerror: "Password must be 8+ characters, contain at least 1 capital letter, 1 lowercase letter, and a number.", token: token});
		return;
	};

	// Validate that there is a single user with that token, then render password reset page
	User.findOne({token: token}, 'username', function (err, user) {
		if (err) {
			res.redirect('/login?expired=true');
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
								
								// EXO Rate Limit: 30 messages / min, 10k per day
								const host = req.headers.host;
								const resetURL = "https://"+host+"/reset/";
								mailer.sendEmail({ 
									from: "SimpleWave <noreply@dev.simplewave.ca>", 
									to: username, 
									subject: "Your password has been recently changed", 
									html: "Your SimpleWave password has been recently changed. If this wasn't you, please reset your password here: " + resetURL
								});
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

app.get('/checkout', async (req, res) => {
	const merchantID = process.env.MERCHANTID; //Converge 6 or 7-Digit Account ID *Not the 10-Digit Elavon Merchant ID*
	//const merchantUserID = "myfree"; //Converge User ID *MUST FLAG AS HOSTED API USER IN CONVERGE UI*
	//const merchantPinCode = "5QIKCV"; //Converge PIN (64 CHAR A/N)

	const merchantUserID = process.env.MERCHANTUSERID; //Converge User ID *MUST FLAG AS HOSTED API USER IN CONVERGE UI*
	const merchantPinCode = process.env.MERCHANTPINCODE; //P Converge PIN (64 CHAR A/N)

	const url = "https://api.demo.convergepay.com/hosted-payments/transaction_token"; // URL to Converge demo session token server
	//const url = "https://demo.myvirtualmerchant.com/VirtualMerchantDemo/process.do";
	// POST only url = /virtual-merchant/process.do
	// const url = "https://api.convergepay.com/hosted-payments/transaction_token"; // URL to Converge production session token server

	/*Payment Field Variables*/

	// In this section, we set variables to be captured by the JavaScript file and passed to Converge in the POST request.
	//const firstname = req.body.ssl_first_name; //Post first name
	//const lastname = req.body.ssl_last_name; //Post first name
	//const amount = req.body.ssl_amount; //Post Tran Amount
	const amount = 100;

	const data = new URLSearchParams();
	data.append('ssl_merchant_id', merchantID);
	data.append('ssl_user_id', merchantUserID);
	data.append('ssl_pin', merchantPinCode);
	data.append('ssl_transaction_type', 'CCSALE');
	data.append('ssl_first_name', 'Test');
	data.append('ssl_last_name', 'User');
	data.append('ssl_get_token', 'Y');
	data.append('ssl_add_token', 'Y');
	data.append('ssl_amount', amount);
	//data.append('ssl_show_form', true);

	try {
		const response = await axios.post(url, data);
		const sessionToken = response.data;
		//const sessionToken = "ABCD";
		console.log(sessionToken);
		//res.json({ token: sessionToken});
		//res.render("checkout", { token: sessionToken });
		res.send(sessionToken); //temp fix to render HTML response from converge
		//return sessionToken;
	} catch (error) {
		console.error(error);
		res.render("checkout", { token: "FAILED" });
	}
});

app.listen(8080, () => {
	console.log("Listening on port 8080");
});