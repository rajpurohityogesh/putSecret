require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose=require("mongoose");
// const bcrypt=require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const FacebookStrategy =require("passport-facebook").Strategy;
const findOrCreate=require("mongoose-findorcreate");

// const saltRounds = 10;

const app = express();


// All app.uses

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");

app.use(session({
    secret: "OurLittleSecret",
    resave : false,
    saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session({secret:"thisIsASecret"}));


// Mongoose Connection
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser:true, useUnifiedTopology:true });
mongoose.set("useCreateIndex",true);


// Our User Schema

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    secret: String
});


// Adding plugins to schema

userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);


// Create model from schema

const User= new mongoose.model("User",userSchema);


// Serialize and Deserialize

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
});
  
passport.deserializeUser(function(obj, done) {
    done(null, obj);
});


// passport.use(new FacebookStrategy({
//     clientID: process.env.FACEBOOK_APP_ID,
//     clientSecret: process.env.FACEBOOK_APP_SECRET,
//     callbackURL: "http://localhost:3000/auth/facebook/secret"
//   },
//   function(accessToken, refreshToken, profile, cb) {
//     User.findOrCreate({ facebookId: profile.id }, function (err, user) {
//       return cb(err, user);
//     });
//   }
// ));

passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: process.env.FACEBOOK_CALLBACK_URL,
        // profileFields: ["id","email", "name"]
      },
      function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
        // const { email, first_name, last_name } = profile._json;
        // const userData = {
        //   email,
        //   firstName: first_name,
        //   lastName: last_name
        // };
        // new userModel(userData).save();
        // done(null, profile);
      }
    )
  );




// GET requests

app.get("/",(req,res)=>{
    res.render("home");
});

app.get("/login",(req,res)=>{
    res.render("login");
});

app.get("/register",(req,res)=>{
    res.render("register");
});

app.get('/auth/facebook',
  passport.authenticate("facebook",{ scope: "profile" }));    

app.get("/auth/facebook/secrets",(req,res)=>{
    passport.authenticate("facebook", {
        successRedirect: "/secrets",
        failureRedirect: "/register"
    })
})

app.get("/secrets",(req,res)=>{
    if(req.isAuthenticated()) {
        User.find({"secret": {$ne : null}},(err,foundUsers)=>{
            if(err){
                console.log(err);
            } else {
                if(foundUsers) {
                    res.render("secrets",{usersWithSecret:foundUsers});
                }
            }
        });
    } else {
        res.redirect("/login");
    }
});

app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout",(req,res)=>{
    req.logOut();
    res.redirect("/");
})


// ...................................................POST requests.................................................


app.post("/register",(req,res)=>{

    User.register({username: req.body.username},req.body.password, (err,user)=>{
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            })
        }
    })
    
});

app.post("/login",(req,res)=>{

    const user= new User({
        username:req.body.username,
        password:req.body.password
    }); 
    
    req.logIn (user,(err)=>{
        if(err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets");
            })
        }
    });
});

app.post("/submit",(req,res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id,(err,foundUser)=>{
        if(err) {
            console.log(err);
        } else {
            if(foundUser) {
                foundUser.secret=submittedSecret;
                foundUser.save(()=> { res.redirect("/secrets"); });
            }
        }
    })
})

app.listen(3000, ()=>{
    console.log("Server is running on port 3000!");
});
