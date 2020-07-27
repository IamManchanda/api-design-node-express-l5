import config from "../config";
import { User } from "../resources/user/user.model";
import jwt from "jsonwebtoken";

export const newToken = (user) => {
  return jwt.sign({ id: user.id }, config.secrets.jwt, {
    expiresIn: config.secrets.jwtExp,
  });
};

export const verifyToken = (token) =>
  new Promise((resolve, reject) => {
    jwt.verify(token, config.secrets.jwt, (err, payload) => {
      if (err) return reject(err);
      resolve(payload);
    });
  });

export const signup = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send({
      message: "Both Email and Password are required",
    });
  }
  try {
    const user = await User.create({ email, password });
    const token = newToken(user);
    return res.status(201).send({ token });
  } catch (e) {
    console.error(e);
    return res.status(500).end();
  }
};

export const signin = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send({
      message: "Both Email and Password are required",
    });
  }
  const user = await User.findOne({
    email,
  })
    .select("email password")
    .exec();
  if (!user) {
    return res.status(401).send({
      message: "Invalid email and password combination",
    });
  }
  try {
    const match = await user.checkPassword(password);
    if (!match) {
      return res.status(401).send({
        message: "Invalid email and password combination",
      });
    }
    const token = newToken(user);
    return res.status(201).send({ token });
  } catch (e) {
    console.error(e);
    return res.status(500).end();
  }
};

export const protect = async (req, res, next) => {
  next();
};
