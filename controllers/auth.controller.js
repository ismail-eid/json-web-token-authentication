const { PrismaClient } = require('@prisma/client');
const config = require('../config/auth.config');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const prisma = new PrismaClient();
const createToken = async (user) => {
  const expiredAt = new Date();
  expiredAt.setSeconds(expiredAt.getSeconds() + config.jwtRefreshExpiration);
  const token = uuidv4();
  const refreshToken = await prisma.refresh_token.create({
    data: {
      token,
      expiryDate: expiredAt,
      user: { connect: { id: user.id } }
    }
  })
  return refreshToken;
}
const verifyExpiration = (token) => {
  return token.expiryDate.getTime() < (new Date()).getTime();
}
exports.signup = async (req, res) => {
  if (!req.body.roles.length) {
    req.body.roles = [ { role_id: 1 } ]
  }
  const user = await prisma.users.create({
    data: {
      username: req.body.username,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 8),
      users_roles: {
        createMany: {
          data: req.body.roles
        }
      }
    }
  })
  if (user) {
    res.status(201).send({ message: 'User was registered successfully!' });
  }
}
exports.signin = async (req, res) => {
  const user = await prisma.users.findUnique({
    where: { username: req.body.username },
    include: { users_roles: true }
  })
  if (!user) {
    res.status(404).send({ message: 'User not found.' });
    return;
  }
  const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
  if (!passwordIsValid) {
    res.status(401).send({
      accessToken: null,
      message: 'Invalid Password!'
    })
  }
  const token = jwt.sign({ id: user.id }, config.secret, { expiresIn: config.jwtExpiration });
  const refreshToken = await createToken(user)
  res.status(200).send({
    ...user,
    accessToken: token,
    refreshToken
  })
}
exports.refreshToken = async (req, res) => {
  const { refreshToken: requestToken } = req.body;
  if (!requestToken) {
    return res.status(403).send({ message: 'Refresh Token is required!' });
  }
  const refreshToken = await prisma.refresh_token.findUnique({
    where: { token: requestToken },
    include: {
      user: true
    }
  })
  if (!requestToken) {
    return res.status(403).send({ message: 'Refresh token is not in database!' })
  }
  if (verifyExpiration(refreshToken.token)) {
    prisma.refresh_token.delete({ where: { id: refreshToken.id } });
    return res.status(403).send({ message: 'Refresh token was expired. Please make a new signin request'});
  }
  const user = refreshToken.user;
  const newAccessToken = jwt.sign({ id: user.id}, config.secret, {
    expiresIn: config.jwtExpiration
  })
  return res.status(200).send({
    accessToken: newAccessToken,
    refreshToken: refreshToken.token
  })
}