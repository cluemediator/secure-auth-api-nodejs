const jwt = require('jsonwebtoken');
const moment = require('moment');
const randtoken = require('rand-token');
const ms = require('ms');

const dev = process.env.NODE_ENV !== 'production';

// refresh token list to manage the xsrf token
const refreshTokens = {};

// cookie options to create refresh token
const COOKIE_OPTIONS = {
  // domain: "localhost",
  httpOnly: true,
  secure: !dev,
  signed: true
};

// generate tokens and return it
function generateToken(user) {
  //1. Don't use password and other sensitive fields
  //2. Use the information that are useful in other parts
  if (!user) return null;

  const u = {
    userId: user.userId,
    name: user.name,
    username: user.username,
    isAdmin: user.isAdmin
  };

  // generat xsrf token and use it to generate access token
  const xsrfToken = randtoken.generate(24);

  // create private key by combining JWT secret and xsrf token
  const privateKey = process.env.JWT_SECRET + xsrfToken;

  // generate access token and expiry date
  const token = jwt.sign(u, privateKey, { expiresIn: process.env.ACCESS_TOKEN_LIFE });

  // expiry time of the access token
  const expiredAt = moment().add(ms(process.env.ACCESS_TOKEN_LIFE), 'ms').valueOf();

  return {
    token,
    expiredAt,
    xsrfToken
  }
}

// generate refresh token
function generateRefreshToken(userId) {
  if (!userId) return null;

  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: process.env.REFRESH_TOKEN_LIFE });
}

// verify access token and refresh token
function verifyToken(token, xsrfToken = '', cb) {
  const privateKey = process.env.JWT_SECRET + xsrfToken;
  jwt.verify(token, privateKey, cb);
}

// return basic user details
function getCleanUser(user) {
  if (!user) return null;

  return {
    userId: user.userId,
    name: user.name,
    username: user.username,
    isAdmin: user.isAdmin
  };
}

// handle the API response
function handleResponse(req, res, statusCode, data, message) {
  let isError = false;
  let errorMessage = message;
  switch (statusCode) {
    case 204:
      return res.sendStatus(204);
    case 400:
      isError = true;
      break;
    case 401:
      isError = true;
      errorMessage = message || 'Invalid user.';
      clearTokens(req, res);
      break;
    case 403:
      isError = true;
      errorMessage = message || 'Access to this resource is denied.';
      clearTokens(req, res);
      break;
    default:
      break;
  }
  const resObj = data || {};
  if (isError) {
    resObj.error = true;
    resObj.message = errorMessage;
  }
  return res.status(statusCode).json(resObj);
}

// clear tokens from cookie
function clearTokens(req, res) {
  const { signedCookies = {} } = req;
  const { refreshToken } = signedCookies;
  delete refreshTokens[refreshToken];
  res.clearCookie('XSRF-TOKEN');
  res.clearCookie('refreshToken', COOKIE_OPTIONS);
}

module.exports = {
  refreshTokens,
  COOKIE_OPTIONS,
  generateToken,
  generateRefreshToken,
  verifyToken,
  getCleanUser,
  handleResponse,
  clearTokens
}
