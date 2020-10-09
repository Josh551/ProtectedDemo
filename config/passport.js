const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const mongoose = require("mongoose");
const User = mongoose.model("users");
const keys = require("../config/keys");

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = keys.secretOrKey;

module.exports = (passport) => {
  passport.use(
    //callback function jwt_payload includes user data
    new JwtStrategy(opts, (jwt_payload, done) => {
      //user data is found by id
      User.findById(jwt_payload.id)
        .then((user) => {
          if (user) {
            //if user exists in database,user is mapped to user
            return done(null, user);
          }
          //if user does not exist in database,user is mapped to false
          return done(null, false);
        })
        .catch((err) => console.log(err));
    })
  );
};
