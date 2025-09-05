require('dotenv').config();
const sanitizeHTML = require('sanitize-html');
const express = require('express');
const db = require('better-sqlite3')('ourApp.db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
// improve db speed
db.pragma('journal_mode = WAL');
// data base starts here

// db.prepare('DROP TABLE IF EXISTS posts').run();

const createTables = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body TEXT NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id)
    )
    `
  ).run();
});

createTables();

// database setup ends here

const app = express();
// setting view engine to ejs
app.set('view engine', 'ejs');
// getting the value from our request
app.use(
  express.urlencoded({
    extended: false,
  })
);
// loading our static files eg css images etc
app.use(express.static('public'));
app.use(cookieParser());
// middleware
app.use(function (req, res, next) {
  res.locals.errors = [];
  // try to decode incoming cookie
  try {
    const decoded = jwt.verify(req.cookies.oursimpleapp, process.env.JWTSECRET);
    req.user = decoded;
  } catch (error) {
    req.user = false;
  }
  res.locals.user = req.user;

  next();
});

app.get('/', (req, res) => {
  if (req.user) {
    const postStatement = db.prepare(`SELECT * FROM posts WHERE authorid = ?`);
    const posts = postStatement.all(req.user.userId);
    const username = req.user.userName;
    return res.render('dashboard', { posts, username });
  }
  res.render('homepage');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/logout', (req, res) => {
  res.clearCookie('oursimpleapp');
  res.redirect('/');
});

app.post('/login', (req, res) => {
  const errors = [];
  if (typeof req.body.username !== 'string') req.body.username = '';
  if (typeof req.body.password !== 'string') req.body.password = '';
  if (req.body.username.trim() === '' || req.body.password === '')
    errors.push('Invalid username / password.');

  if (errors.length) {
    return res.render('login', { errors });
  }
  const userInQuestion = db.prepare('SELECT * FROM users WHERE username = ?');
  const user = userInQuestion.get(req.body.username);

  if (!user) {
    errors.push('Invalid username / password');
    return res.render('login', { errors });
  }
  const matchOrNot = bcrypt.compareSync(req.body.password, user.password);
  if (!matchOrNot) {
    errors.push('Invalid username / password');
  }
  // give them a cookie
  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      userId: user.id,
      userName: user.username,
      skyColor: 'blue',
    },
    process.env.JWTSECRET
  );
  res.cookie('oursimpleapp', token);
  res.redirect('/');
});

// a custom middle ware that checks if i am logged in

function mustBeLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect('/');
}

app.get('/create-post', mustBeLoggedIn, (req, res) => {
  res.render('create-post');
});

function sharedPostValidation(req) {
  const errors = [];
  if (typeof req.body.title !== 'string') req.body.title = '';
  if (typeof req.body.body !== 'string') req.body.body = '';

  // trim - sanitize or strip out html
  req.body.title = sanitizeHTML(req.body.title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  req.body.body = sanitizeHTML(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!req.body.title || !req.body.body) errors.push('Field cannot be empty');
  return errors;
}

app.get('/edit-post/:id', mustBeLoggedIn, (req, res) => {
  // look up the post in question
  const statement = db.prepare('SELECT posts.* FROM posts WHERE id = ? ');
  const post = statement.get(req.params.id);

  if (!post) {
    return res.redirect('/');
  }
  // if not the author redirect to homepage
  if (post.authorid !== req.user.userId) {
    return res.redirect('/');
  }

  // otherwise render the edit page
  res.render('edit-post', { post });
});

app.post('/edit-post/:id', mustBeLoggedIn, (req, res) => {
  const statement = db.prepare('SELECT posts.* FROM posts WHERE id = ?');
  const post = statement.get(req.params.id);
  if (!post) {
    return res.redirect('/');
  }
  // if not the author redirect to homepage
  if (post.authorid !== req.user.userId) {
    return res.redirect('/');
  }

  const errors = sharedPostValidation(req);
  if (errors.length) {
    return res.render('edit-post', { errors });
  }

  // update database
  const updateStatement = db.prepare('UPDATE posts SET title = ?, body = ? WHERE id = ?');
  updateStatement.run(req.body.title, req.body.body, req.params.id);

  res.redirect(`/post/${req.params.id}`);
});

app.post('/delete-post/:id', mustBeLoggedIn, (req, res) => {
  const statement = db.prepare('SELECT posts.* FROM posts WHERE id = ?');
  const post = statement.get(req.params.id);
  if (!post) {
    return res.redirect('/');
  }
  // if not the author redirect to homepage
  if (post.authorid !== req.user.userId) {
    return res.redirect('/');
  }

  const deleteStatement = db.prepare(`DELETE FROM posts WHERE id = ?`);
  deleteStatement.run(req.params.id);

  res.redirect('/');
});

app.get('/post/:id', (req, res) => {
  const statement = db.prepare(
    'SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?'
  );
  const post = statement.get(req.params.id);
  if (!post) {
    return res.redirect('/');
  }
  const isAuthor = post.authorid === req.user.userId;
  res.render('single-post', { post, isAuthor });
});

app.post('/create-post', mustBeLoggedIn, (req, res) => {
  // validating title and body field
  const errors = sharedPostValidation(req);
  if (errors.length) {
    return res.render('create-post', { errors });
  }

  // save into database
  const ourStatement = db.prepare(
    'INSERT INTO posts (title,body,authorid,createdDate) VALUES(?,?,?,?)'
  );
  const result = ourStatement.run(
    req.body.title,
    req.body.body,
    req.user.userId,
    new Date().toISOString()
  );

  const getPostsStatement = db.prepare('SELECT * FROM posts WHERE ROWID = ?');
  const post = getPostsStatement.get(result.lastInsertRowid);

  res.redirect(`/post/${post.id}`);

  // res.send('thank you');
});

app.post('/register', (req, res) => {
  const errors = [];
  if (typeof req.body.username !== 'string') req.body.username = '';
  if (typeof req.body.password !== 'string') req.body.password = '';
  req.body.username = req.body.username.trim();
  if (!req.body.username) errors.push('you must provide a username.');
  if (req.body.username && req.body.username.length < 3)
    errors.push('Username must be greater than 3 characters');
  if (req.body.username && req.body.username.length > 10)
    errors.push('Username must not exceed 10 characters');
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push('Username cannot use special characters');

  // check if username exists already
  const usernameStatus = db.prepare('SELECT * FROM users WHERE username = ?');
  const userExists = usernameStatus.get(req.body.username);
  if (userExists) errors.push('Username already exists');

  // password validation

  if (!req.body.password) errors.push('you must provide a Password.');
  if (req.body.password && req.body.password.length < 8)
    errors.push('Password must be greater than 8 characters');
  if (req.body.password && req.body.password.length > 20)
    errors.push('Password must not exceed 20 characters');
  if (errors.length) {
    return res.render('homepage', { errors });
  }
  // save the new user into a database
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);
  const ourStatement = db.prepare('INSERT INTO users (username, password) VALUES(?,?)');
  const result = ourStatement.run(req.body.username, req.body.password);
  const lookupStatement = db.prepare('SELECT * FROM users WHERE ROWID = ? ');
  const ourUser = lookupStatement.get(result.lastInsertRowid);
  // log the user in by giving them a cookie
  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: 'blue',
      userId: ourUser.id,
      userName: ourUser.username,
    },
    process.env.JWTSECRET
  );
  res.cookie('oursimpleapp', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24,
  });
  res.redirect('/');
});
app.listen(3000);
