require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//this is for simple mongoosse encryption...
// const encrypt = require("mongoose-encryption");
//this is for the hash code encryption....
// const md5 = require("md5");
//this is for the bcrypt...
// const bcrypt = require("bcrypt");
//this is for passport passport-local passport-local-mongoose express-session
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");





const app = express();
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
  secret: "this is our littel secret",
  resave: false,
  saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session())
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileUrl:"https://www.google.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));






mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true,useUnifiedTopology: true});
mongoose.set("useCreateIndex",true);
const userSchema = new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String
});


// userSchema.plugin(encrypt,{secret : process.env.KEY , excludeFromEncryption:['email']});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);
// const saltRounds = 10; ////bcrypt salt rounds...

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id,function(err,user){
    done(null, user);
  });
});

app.get("/",function(req,res){
  res.render("home");
});
app.route("/login").get(function(req,res){
  res.render("login");
}).post(function(req,res){
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email:username},function(err,foundeduser){
  //   if(!err){
  //     if(foundeduser){
  //       bcrypt.compare(password,foundeduser.password,function(err,result){
  //         if(result===true){
  //           res.render("secrets");
  //         }
  //       })}
  //   }else{
  //     console.log(err);
  //   }
  // })

  const user = new User({
    username : req.body.username,
    password : req.body.password
  });

  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req , res , function(){  res.redirect("/secrets")  } );}  });
    });

app.route("/secrets").get(function(req,res){
  User.find({secret:{$ne:null}},function(err,foundUsers){
    if(err){console.log(err);}else{if(foundUsers){res.render("secrets",{usersWithSecrets:foundUsers})}}});
});

app.route("/register").get(function(req,res){
  res.render("register");
}).post(function(req,res){
  // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
  //
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err){
  //     if(!err){
  //       res.render("secrets");
  //     }else{
  //         console.log(err);
  //     }
  //   })
  // });

    User.register({username: req.body.username},req.body.password,function(err,user){
      if(err){
        console.log(err);
        res.redirect("/register");
      }else{
        passport.authenticate("local")(req , res , function(){
          res.redirect("/secrets")
        })}
    });

});

app.get("/auth/google",  passport.authenticate('google', { scope: ["profile"]}));
app.get("/auth/google/secrets", passport.authenticate('google', { failureRedirect: "/login" }),function(req,res){
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});
app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.route("/submit").get(function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
}).post(function(req, res){
  const submitedSecret = req.body.secret;
  User.findById(req.user.id,function(err,foundUser){
    if(err){console.log(err);}else{if(foundUser){foundUser.secret=submitedSecret;foundUser.save(function(){res.redirect("/secrets")});}}
  });
});

app.listen(3000,function(){
  console.log("Server is running on port 3000");
});
