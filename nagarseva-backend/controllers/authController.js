const { validationResult } = require('express-validator');
const User = require('../models/User');

const setAuthCookie = (res, token) => {
  const isProd = process.env.NODE_ENV === 'production';

  res.cookie('token', token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
};

const sanitizeUserResponse = (userDoc) => {
  if (!userDoc) {
    return null;
  }

  if (typeof userDoc.toSafeObject === 'function') {
    return userDoc.toSafeObject();
  }

  const fallback = userDoc.toObject ? userDoc.toObject() : userDoc;
  delete fallback.password;

  if (fallback.aadhaarNumber) {
    const digitsOnly = String(fallback.aadhaarNumber).replace(/\D/g, '');
    fallback.aadhaarNumber = digitsOnly.length >= 4
      ? `XXXXXXXX${digitsOnly.slice(-4)}`
      : 'XXXXXXXX';
  }

  return fallback;
};

const register = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const {
      name,
      mobile,
      email,
      password,
      aadhaarNumber,
      address,
      ward
    } = req.body;

    console.log('[AUTH] Register request received for mobile:', mobile);

    const existingMobile = await User.findOne({ mobile });
    if (existingMobile) {
      return res.status(409).json({
        success: false,
        message: 'Mobile number is already registered.'
      });
    }

    if (email) {
      const existingEmail = await User.findOne({ email: email.toLowerCase() });
      if (existingEmail) {
        return res.status(409).json({
          success: false,
          message: 'Email is already registered.'
        });
      }
    }

    const user = await User.create({
      name,
      mobile,
      email: email ? email.toLowerCase() : undefined,
      password,
      aadhaarNumber,
      address,
      ward,
      role: 'citizen'
    });

    const token = user.generateJwt();
    setAuthCookie(res, token);

    console.log('[AUTH] Citizen registered successfully:', user._id.toString());

    return res.status(201).json({
      success: true,
      message: 'Registration successful.',
      token,
      user: sanitizeUserResponse(user)
    });
  } catch (error) {
    console.log('[AUTH] Registration error:', error.message);
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { mobile, email, password } = req.body;

    console.log('[AUTH] Login request received:', {
      mobile: mobile || null,
      email: email || null
    });

    const query = {};

    if (email) {
      query.email = email.toLowerCase();
    } else {
      query.mobile = mobile;
    }

    const user = await User.findOne(query).select('+password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.'
      });
    }

    if (email && user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admin can login with email.'
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Your account is inactive. Contact administrator.'
      });
    }

    const isPasswordMatched = await user.comparePassword(password);
    if (!isPasswordMatched) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.'
      });
    }

    const token = user.generateJwt();
    setAuthCookie(res, token);

    console.log('[AUTH] Login successful for user:', user._id.toString());

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      token,
      user: sanitizeUserResponse(user)
    });
  } catch (error) {
    console.log('[AUTH] Login error:', error.message);
    next(error);
  }
};

const logout = async (req, res, next) => {
  try {
    res.cookie('token', '', {
      httpOnly: true,
      expires: new Date(0)
    });

    console.log('[AUTH] User logged out successfully.');

    return res.status(200).json({
      success: true,
      message: 'Logout successful.'
    });
  } catch (error) {
    console.log('[AUTH] Logout error:', error.message);
    next(error);
  }
};

const getCurrentUser = async (req, res, next) => {
  try {
    const currentUser = await User.findById(req.user._id);

    if (!currentUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found.'
      });
    }

    return res.status(200).json({
      success: true,
      user: sanitizeUserResponse(currentUser)
    });
  } catch (error) {
    console.log('[AUTH] Get current user error:', error.message);
    next(error);
  }
};

const changePassword = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found.'
      });
    }

    const isCurrentPasswordValid = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect.'
      });
    }

    user.password = newPassword;
    await user.save();

    const token = user.generateJwt();
    setAuthCookie(res, token);

    console.log('[AUTH] Password changed successfully for user:', user._id.toString());

    return res.status(200).json({
      success: true,
      message: 'Password changed successfully.'
    });
  } catch (error) {
    console.log('[AUTH] Change password error:', error.message);
    next(error);
  }
};

module.exports = {
  register,
  login,
  logout,
  getCurrentUser,
  changePassword
};
