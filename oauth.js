const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');

const helmet = require('helmet');

//do the authentication with google
const passport = require('passport');

const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
const { verify } = require('crypto');

require('dotenv').config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',
  clientID: config.CLIENT_ID,//used for connecting our app with google,thats how google identify our app
  clientSecret: config.CLIENT_SECRET,//keeps the access tokens we create secure
};

//if we rwcieved an access token it means that the cradentials for that user are valid ,google already chacked it
//but if we get password we will compare it with the value in are database and decide if the cradentials are valid
function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log('Google profile', profile);
  done(null, profile);//to supply passport with the user which authenticated
}

//sets up the passport strategy which determine which strategy passport will use to authenticate
//the callbach called when the user is authorized
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session(the user data) to the cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Read(load) the session from the cookie
passport.deserializeUser((id, done) => {
  done(null, id);
});

const app = express();

app.use(helmet());

app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000,//how long the session last untill the user has to login again
  keys: [ config.COOKIE_KEY_1, config.COOKIE_KEY_2 ],//list of secret values that kepps the cookie secure 
  //by signing the cookie so only the server can decide what the session contains, the server will sign the 
  //cookies its sends to the browser with this secret key and verify incomming cookies to make suru that they created with that secret key
}));


app.use(passport.initialize()); //passport middleware which helps us set up passport

//authenticate the session that been sent to our server using the keys above and validates
//that everything is signd as it should be, then sets the value of the user property on our request obj to
//contain users identity 
app.use(passport.session());

/*function checkLoggedIn(req, res, next) { 
  console.log('Current user is:', req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({
      error: 'You must log in!',
    });
  }
  next();
}*/

//the first request, the scope spicify which data we ask from 
//google when everything succeds
app.get('/auth/google', 
  passport.authenticate('google', {
    scope: ['email'],
  }));

  //request for google callback
  //the passport.authenticate middleware handles the entire flow from when google sends us the 
  //authentication code response and our request back to google to get the access token and google
  // response with the access token
app.get('/auth/google/callback', 
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
  }), 
  (req, res) => {
    console.log('Google called us back!');
  }
);

app.get('/auth/logout', (req, res) => {
  req.logout(); //Removes req.user and clears any logged in session
  return res.redirect('/');
});


app.get('/failure', (req, res) => {
  return res.send('Failed to log in!');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

//set the path for the server
https.createServer({
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
  console.log(`Listening on port ${PORT}...`);
});