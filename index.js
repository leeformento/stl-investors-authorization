const express = require('express');
const helmet = require('helmet')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./data/dbConfig.js');

const server = express();

server.use(express.json());
server.use(helmet());

server.get('/', (req, res) => {
    res.send('Whazzahh!');
  });

server.post('/register', (req,res) => {
    const credentials = req.body;
    const hash = bcrypt.hashSync(credentials.password, 2)
    credentials.password = hash;
    db('users')
    .insert(credentials)
    .then(ids => {
        const id = ids[0];
        res.status(201).json({newUserId: id})
    })
})
server.get('/users', protected, (req, res) => {
    db('users')
        .select('id', 'username')
        .then(users => {
        res.json(users);
    })
    .catch(err => res.send(err));
});

const jwtSecret = 'kyah, pembarya!';

function generateToken(user) {
    const jwtPayload = {
        ...user,
        hello: `${user}`,
        subject: user.id,
        role: 'admin'
    }
    const jwtOptions = {
        expiresIn: '1hr'
    }
    return jwt.sign(jwtPayload, jwtSecret, jwtOptions)
}

server.post('/login', (req, res) => {
    const credentials = req.body;
    db('users')
    .where({ username: credentials.username })
    .first()
    .then(user => {
        if (user && bcrypt.compareSync(credentials.password, user.password)) {
            const token = generateToken(user)
            res.status(201).json({ Welcome: user.username, token});
        } else {
            res.status(401).json({ message: 'You shall not pass!'})
        }
    })
})

function protected(req, res, next) {
    const token = req.headers.authorization;
    if (token) {
        jwt.verify(token, jwtSecret, (err, decodedToken) => {
            if (err) {
                res.status(401).json({ message: 'Invalid token, you shall not pass'})
            } else {
                req.decodedToken = decodedToken;
                console.log('\n***decoded token info **\n', req.decodedToken);
                next();
            }
        })
    } else {
        res.status(401).json({ message: 'no token provided'})
    }
}

const port = process.env.PORT || 4443;
server.listen(port, () => console.log(`===Party at ${port} ===`))