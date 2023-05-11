require("./utils");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3020;
const app = express();

const Joi = require("joi");

//Expires after 1 hour
const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* Secret Information Section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* End Secret Information Section */

var { database } = require("./databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    var html = `
        <h1>Welcome to Kenneth's website!</h1>
        <a href='/login'>Login</a>
        <br><br>
        <a href='/signUp'>Signup</a>
    `;
    res.send(html);
  } else {
    res.redirect("/loggedIn");
  }
});

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/about", (req, res) => {
  var color = req.query.color;

  res.send("<h1 style='color:" + color + ";'>Kenneth Ahn</h1>");
});

app.get("/contact", (req, res) => {
  var missingEmail = req.query.missing;
  var html = `
        Email Address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='Email'>
            <button>Submit</button>
        </form>
    `;
  if (missingEmail) {
    html += "<h2 style='color:red;'>Please enter an email address</h2>";
  }
  res.send(html);
});

app.post("/submitEmail", (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.send("Thank you for subscribing with your email: " + email);
  }
});

app.get("/signUp", (req, res) => {
  var html = `
    Sign Up:
    <br></br>
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    </br>
    <input name='email' type='email' placeholder='email'>
    </br>
    <input name='password' type='password' placeholder='password'>
    <br></br>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    var errorMessage = validationResult.error.details[0].message;
    res.send(
      `Error: ${errorMessage}. Please <a href="/signup">try again!</a>.`
    );
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.username = username;

  res.redirect("/");
});

app.get("/login", (req, res) => {
  var msg = req.query.msg || "";
  var html = `
      Login:
      <form action='/loggingin' method='post'>
      <br></br>
      <input name='email' type='email' placeholder='email'>
      </br>
      <input name='password' type='password' placeholder='password'>
      <br></br>
      <button>Login</button>
      </form>
      <p id='msg'> ${msg} </p>
    `;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login?msg=Invalid Email/Password!");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ username: 1, email: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("User not found");
    res.redirect("/login?msg=Invalid Email/Password!");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("Correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedIn");
    return;
  } else {
    console.log("Incorrect password");
    res.redirect("/login?msg=Invalid Email/Password!");
    return;
  }
});

app.get("/loggedIn", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }

  var html = `
  <h1>Hello ${req.session.username}!</h1>
  </br>
  <a href='/members'>Members</a>
  <br></br>
  <a href='/logout'>Logout</a>
  `;
  res.send(html);
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

const imageURL = ["dog1.jpeg", "dog2.jpeg", "dog3.jpeg"];

app.get("/dog/:id", (req, res) => {
  var dog = req.params.id;

  if (dog == 1) {
    res.send("dog1: <img src='/dog1.jpeg' style='width:250px;'>");
  } else if (dog == 2) {
    res.send("dog2: <img src='/dog2.jpeg' style='width:250px;'>");
  } else if (dog == 3) {
    res.send("dog3: <img src='/dog3.jpeg' style='width:250px;'>");
  } else {
    res.send("Invalid dog id: " + dog);
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }

  const username = req.session.username;
  const imageIndex = Math.floor(Math.random() * imageURL.length);
  const image = imageURL[imageIndex];

  const html = `
        <h1>Hello, ${username}!</h1>
        <img src='/${image}' style='width:30%; height:auto;'>
        <br></br>
        <a href='/logout'>Logout</a>
    `;
  res.send(html);
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
