const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protectRoute = async (req, res, next) => {
  try {
    let token;

    if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      res.status(401);
      throw new Error('Access denied. Authentication token missing.');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      res.status(401);
      throw new Error('Invalid token. User does not exist.');
    }

    if (!user.isActive) {
      res.status(403);
      throw new Error('Your account has been deactivated. Contact administrator.');
    }

    req.user = user;
    console.log(`[AUTH] Authenticated user ${user._id} (${user.role})`);
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      res.status(401);
      return next(new Error('Invalid or expired authentication token.'));
    }

    return next(error);
  }
};

const authorizeRoles = (...roles) => (req, res, next) => {
  try {
    if (!req.user) {
      res.status(401);
      throw new Error('Unauthorized access. Please login first.');
    }

    if (!roles.includes(req.user.role)) {
      res.status(403);
      throw new Error(`Access denied. Allowed roles: ${roles.join(', ')}`);
    }

    next();
  } catch (error) {
    next(error);
  }
};

module.exports = {
  protectRoute,
  authorizeRoles
};
