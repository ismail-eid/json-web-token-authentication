const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const ROLES = ['user', 'admin', 'moderator'];
const checkDuplicateUsernameOrEmail = async (req, res, next) => {
  // Username
  const findUserByUsername = await prisma.users.findUnique({
    where: {
      username: req.body.username
    }
  })
  const findUserByEmail = await prisma.users.findUnique({
    where: {
      email: req.body.email
    }
  })
  if (findUserByUsername || findUserByEmail) {
    res.status(400).send({
      message: `Failed! ${findUserByUsername ? 'Username' : 'Email'} is already in use!`
    })
    return;
  }
  next();
}
const checkRolesExisted = (req, res, next) => {
  if (req.body.roles) {
    for (let i = 0; i < req.body.length; i++) {
      if (!ROLES.includes(req.body.roles[i])) {
        res.status(400).send({
          message: 'Failed! Role does not exist = ' + req.body.roles[i]
        })
        return;
      }
    }
  }
  next();
}
const verifySignUp = {
  checkDuplicateUsernameOrEmail,
  checkRolesExisted
}
module.exports = verifySignUp;
