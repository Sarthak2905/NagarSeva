const crypto = require('crypto');

const ensureCsrfCookie = (req, res, next) => {
  try {
    const isProd = process.env.NODE_ENV === 'production';

    if (!req.cookies.csrfToken) {
      const csrfToken = crypto.randomBytes(32).toString('hex');
      res.cookie('csrfToken', csrfToken, {
        httpOnly: false,
        secure: isProd,
        sameSite: isProd ? 'none' : 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });
      req.cookies.csrfToken = csrfToken;
    }

    next();
  } catch (error) {
    next(error);
  }
};

const csrfProtection = (req, res, next) => {
  try {
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];

    if (safeMethods.includes(req.method)) {
      return next();
    }

    const tokenFromCookie = req.cookies.csrfToken;
    const tokenFromHeader = req.headers['x-csrf-token'];

    let areEqual = false;

    if (tokenFromCookie && tokenFromHeader && tokenFromCookie.length === tokenFromHeader.length) {
      try {
        const cookieTokenBuffer = Buffer.from(tokenFromCookie, 'utf8');
        const headerTokenBuffer = Buffer.from(tokenFromHeader, 'utf8');
        areEqual = crypto.timingSafeEqual(cookieTokenBuffer, headerTokenBuffer);
      } catch (error) {
        areEqual = false;
      }
    }

    if (!areEqual) {
      return res.status(403).json({
        success: false,
        message: 'CSRF token validation failed.'
      });
    }

    return next();
  } catch (error) {
    return next(error);
  }
};

module.exports = {
  ensureCsrfCookie,
  csrfProtection
};
