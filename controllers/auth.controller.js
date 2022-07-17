const { PrismaClient } = require('@prisma/client');
const config = require('../config/auth.config');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const prisma = new PrismaClient();
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
  const token = jwt.sign({ id: user.id }, config.secret, { expiresIn: 86400 });
  res.status(200).send({
    ...user,
    accessToken: token
  })
}