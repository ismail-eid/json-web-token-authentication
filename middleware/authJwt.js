const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const config = require('../config/auth.config');
const prisma = new PrismaClient();
const { TokenExpiredError } = jwt;
const catchError = (err, res) => {
  if (err instanceof TokenExpiredError) {
    return res.status(401).send({ message: 'Unauthorized! access token was expired!' });
  }
  return res.status(401).send({ message: 'Unauthorized!' });
}
const verifyToken = (req, res, next) => {
  let token = req.headers['x-access-token'];
  if (!token) {
    return res.status(403).send({ message: 'No token provided!' })
  }
  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return catchError(err, res);
    }
    req.userId = decoded.id;
    next();
  })
}
const isAdmin = async (req, res, next) => {
  const user = await prisma.users.findUnique({
    where: { id: req.userId },
    include: { users_roles: true }
  })
  const roles = user.users_roles;
  for (const role of roles) {
    if (role.role_id === 2) {
      next();
      return;
    }
  }
  res.status(403).send({ message: 'Require Admin Role!' });
  return;
}
const isModerator = async (req, res, next) => {
  const user = await prisma.users.findUnique({
    where: { id: req.userId },
    include: { users_roles: true }
  })
  const roles = user.users_roles;
  for (const role of roles) {
    if (role.role_id === 3) {
      next();
      return;
    }
  }
  res.status(403).send({ message: 'Require Moderator Role!' });
  return;
}
const isModeratorOrAdmin = async (req, res, next) => {
  const user = await prisma.users.findUnique({
    where: { id: req.userId },
    include: { users_roles: true }
  })
  const roles = user.users_roles;
  for (const role of roles) {
    if (role.role_id === 2 || role.role_id === 3) {
      next();
      return;
    }
  }
  res.status(403).send({ message: 'Require Moderator or Admin Role!' });
  return;
}
const authJwt = {
  verifyToken,
  isAdmin,
  isModerator,
  isModeratorOrAdmin
}
module.exports = authJwt;