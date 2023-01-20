const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
mongoose.set('strictQuery', false);

const _ = require('lodash');
require('dotenv').config();
const sessions = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate')
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
app.use(sessions({
  secret: 'This is Anurag',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/userDB',
  {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true }, // values: email address, googleId, facebookId
  password: String,
  provider: String, // values: 'local', 'google', 'facebook'
  email: String,
  secrets: [String]
});

userSchema.plugin(passportLocalMongoose, {
  usernameField: "username"
});//to hash and salt password and to save in mongodb Database    
userSchema.plugin(findOrCreate);//to find or create

const User = new mongoose.model('user', userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate(
      { username: profile.id },
      {
        provider: "google",
        email: profile._json.email
      },
      function (err, user) {
        return cb(err, user);
      }
    );
  }
));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: 'http://localhost:3000/oauth2/redirect/facebook'
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate(
      { username: profile.id },
      {
        provider: "facebook",
        email: profile._json.email
      },
      function (err, user) {
        return cb(err, user);
      }
    );
  }
));


app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.render('home');
});

app.route('/auth/google')

  .get(passport.authenticate('google', {

    scope: ['profile', 'email']

  }));

app.get('/login/facebook', passport.authenticate('facebook', {
  scope: ['email']
}));

//redirect from google
app.get('/auth/google/secrets', //redirect from google
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

//redirect from facebook
app.get('/oauth2/redirect/facebook',
  passport.authenticate('facebook', { failureRedirect: '/login', failureMessage: true }),
  function (req, res) {
    res.redirect('/secrets');
  });


app.get('/secrets', (req, res) => {
  User.find({secrets:{$ne: null}},(err, userWithSecret) => {
    if (err) {
      console.log(err);
    } else {
      res.render('secrets', {
        users: userWithSecret
      });
    }
  });
  });
app.get('/logout', function (req, res) {
  req.logout(function (err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});
app.route('/register')
  .get((req, res) => {
    res.render('register');
  })
  .post((req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
      if (err) {
        console.log(err);
        res.redirect('/register');
      }
      else {
        passport.authenticate('local')(req, res, () => {
          res.redirect('/secrets');
        });
      }
    });
  });

app.route('/login')
  .get((req, res) => {
    res.render('login');
  })
  .post((req, res) => {
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
    req.login(user, (err) => {
      if (err) {
        console.log(err);
      }
      else {
        passport.authenticate('local')(req, res, () => {
          res.redirect('/secrets');
        })
      };
    });
  });
app.route('/submit')
  .get((req, res) => {
    if (req.isAuthenticated()) {
      res.render('submit');
    }
    else {
      res.redirect('/login');
    }
  })
  .post((req, res) => {
    User.findById(req.user.id, function (err, foundUser) {
      if (err){
          console.log(err);
      }
      else{
          newSecret=req.body.secret;
          foundUser.secrets.push(newSecret);
          foundUser.save();
          res.redirect('/secrets');
      }
  });
  });

app.listen(3000, function () {
  console.log('Server running ar port 3000');
});