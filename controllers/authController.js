const passport = require('passport');
const mongoose = require('mongoose');
const User = mongoose.model('User');
const crypto = require('crypto');
const promisify = require('es6-promisify');
const mail = require('../handlers/mail');

exports.login = passport.authenticate('local', {
  failureRedirect: '/login',
  failureFlash: 'Failed Login!',
  successRedirect: '/',
  successFlash: 'You are now logged in'
});


exports.logout = (req, res) => {
  req.logout();
  req.flash('success', 'You are now logged out!');
  res.redirect('/');
}


exports.isLoggedIn = (req, res, next) => {
  // first check if the user is authenticated
  if(req.isAuthenticated()) {
    return next(); // carry on! They are logged in!
  }
  req.flash('error', 'Oops you must be logged in to do that!');
  res.redirect('/login');
}


exports.forgot = async (req, res) => {
  // 1. See if a user with that email exists
  const user = await User.findOne({ email: req.body.email })
  if (!user) {
    req.flash('error', 'No account with that email exists');
    return res.redirect('/login');
  }

  // 2. Set reset tokens and expiry on their account
  user.resetPasswordToken = crypto.randomBytes(20).toString('hex');
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour from now;
  await user.save();

  // 3. Send them an email with the token
  const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;
  await mail.send({
    user,
    filename: 'password-reset',
    subject: 'Password Reset',
    resetURL,
  });
  req.flash('success', 'You have been emailed a password reset link');

  // 4. Redirect to login page after email has been sent
  res.redirect('/login');

}


exports.confirmToken = async (req, res, next) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() }
  });

  if (!user) {
    req.flash('error', 'Password reset is invalid or has expired');
    return res.redirect('/login');
  }

  res.locals.user = user;
  return next(); // keep it going
}


exports.reset = async (req, res) => {
  res.render('reset', {
    title: 'Reset Your Password'
  });
}


exports.confirmedPasswords = (req, res, next) => {
  if (req.body.password === req.body['password-confirm']) {
    return next(); // keep it going!
  }

  req.flash('error', 'Passwords do not match!');
  res.redirect('back');
}


exports.updatePassword = async (req, res) => {
  const user = res.locals.user;

  // change password
  const setPasswordWithPromise = promisify(user.setPassword, user);
  await setPasswordWithPromise(req.body.password);

  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  const updatedUser = await user.save();

  // log user in
  await req.login(updatedUser);
  req.flash('Success', 'Nice! Your password has been reset! You are now logged in!');
  res.redirect('/');
}