const express = require("express");

const session = require("express-session");

const app = express();

const port = process.env.PORT || 8000;

const node_session_secret = "4ddd127e-2b2d-4bf3-b6c8-c230a065e3d4";

app.use(
  session({
    secret: node_session_secret,
    saveUninitialized: false,
    resave: true,
  })
);

var numPageHits = 0;

app.get("/", (req, res) => {
  if (req.session.numPageHits == null) {
    req.session.numPageHits = 0;
  } else {
    req.session.numPageHits++;
  }
  numPageHits++;
  res.send("You have visited this page " + numPageHits + " times! :D");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
