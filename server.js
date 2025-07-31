const express       = require('express');
const cors          = require('cors');
const dotenv        = require('dotenv');
const passport      = require('passport');
const passportJWT   = require('passport-jwt');
const jwt           = require('jsonwebtoken');
const userService   = require('./user-service.js');

dotenv.config();
const HTTP_PORT = process.env.PORT || 8080;

const ExtractJwt  = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
  secretOrKey:    process.env.JWT_SECRET
};

const strategy = new JwtStrategy(jwtOptions, (jwt_payload, next) => {
  if (jwt_payload && jwt_payload._id && jwt_payload.userName) {
    next(null, { _id: jwt_payload._id, userName: jwt_payload.userName });
  } else {
    next(null, false);
  }
});

passport.use(strategy);

const app = express();

app.use(passport.initialize());
app.use(express.json());
app.use(cors());

app.post("/api/user/register", (req, res) => {
  userService.registerUser(req.body)
    .then(msg => res.json({ message: msg }))
    .catch(err => res.status(422).json({ message: err }));
});

app.post("/api/user/login", (req, res) => {
  userService.checkUser(req.body)
    .then(user => {
      const payload = { _id: user._id, userName: user.userName };
      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });
      res.json({ message: 'login successful', token });
    })
    .catch(err => res.status(422).json({ message: err }));
});

const auth = passport.authenticate('jwt', { session: false });

app.get("/api/user/favourites", auth, (req, res) => {
  userService.getFavourites(req.user._id)
    .then(data => res.json(data))
    .catch(err => res.status(422).json({ error: err }));
});

app.put("/api/user/favourites/:id", auth, (req, res) => {
  userService.addFavourite(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(err => res.status(422).json({ error: err }));
});

app.delete("/api/user/favourites/:id", auth, (req, res) => {
  userService.removeFavourite(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(err => res.status(422).json({ error: err }));
});

app.get("/api/user/history", auth, (req, res) => {
  userService.getHistory(req.user._id)
    .then(data => res.json(data))
    .catch(err => res.status(422).json({ error: err }));
});

app.put("/api/user/history/:id", auth, (req, res) => {
  userService.addHistory(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(err => res.status(422).json({ error: err }));
});

app.delete("/api/user/history/:id", auth, (req, res) => {
  userService.removeHistory(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(err => res.status(422).json({ error: err }));
});

userService.connect()
  .then(() => {
    app.listen(HTTP_PORT, () => {
      console.log(`API listening on: ${HTTP_PORT}`);
    });
  })
  .catch(err => {
    console.error("unable to start the server:", err);
    process.exit(1);
  });
