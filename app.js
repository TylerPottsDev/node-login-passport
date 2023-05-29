const express			= require('express');
const session			= require('express-session');
const hbs				= require('express-handlebars');
const mongoose			= require('mongoose');
const passport			= require('passport');
const localStrategy		= require('passport-local').Strategy;
const bcrypt			= require('bcrypt');
const app				= express();

// 1st party dependencies
var configData = require("./config/connection.js");

// Database
var connectionInfo = configData.getConnectionInfo();
console.log (connectionInfo.DATABASE_URL);
mongoose.connect(connectionInfo.DATABASE_URL, {
	useNewUrlParser: true,
	useUnifiedTopology: true
});

//mongoose.connect("mongodbURL", {
//	useNewUrlParser: true,
//	useUnifiedTopology: true
//});

const UserSchema = new mongoose.Schema({
	username: {
		type: String,
		required: true
	},
	password: {
		type: String,
		required: true
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
		userexists: req.query.userexists
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

app.post('/login', passport.authenticate('local', {
	successRedirect: '/',
	failureRedirect: '/login?error=true'
}));

app.post('/register', async (req, res) => {
	const useremail = req.body.username;
	const password = req.body.password;

	const exists = await User.exists({ username: useremail });

	if (exists) {
		res.redirect('/login?userexists=true');
		return;
	};

	bcrypt.genSalt(10, function (err, salt) {
		if (err) return next(err);
		bcrypt.hash(password, salt, function (err, hash) {
			if (err) return next(err);
			
			const newUser = new User({
				username: useremail,
				password: hash
			});

			newUser.save();

			res.redirect('/login?success=true');
		});
	});
});

app.get('/logout', function (req, res) {
	req.logout();
	res.redirect('/');
});

// Setup our admin user
app.get('/setup', async (req, res) => {
	const exists = await User.exists({ username: "admin" });

	if (exists) {
		res.redirect('/login');
		return;
	};

	bcrypt.genSalt(10, function (err, salt) {
		if (err) return next(err);
		bcrypt.hash("pass", salt, function (err, hash) {
			if (err) return next(err);
			
			const newAdmin = new User({
				username: "admin",
				password: hash
			});

			newAdmin.save();

			res.redirect('/login');
		});
	});
});

app.listen(3000, () => {
	console.log("Listening on port 3000");
});