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

const normalizeStringField = (value, { lower = false } = {}) => {
  if (typeof value !== 'string') {
    return '';
  }

  const normalized = value.trim();
  return lower ? normalized.toLowerCase() : normalized;
};

const logAuthError = (label, error) => {
  if (process.env.NODE_ENV === 'production') {
    console.log(`[AUTH] ${label}: internal error`);
    return;
  }

  console.log(`[AUTH] ${label}:`, error.message);
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

    const safeName = normalizeStringField(name);
    const safeMobile = normalizeStringField(mobile);
    const safeEmail = normalizeStringField(email, { lower: true });
    const safeAadhaar = normalizeStringField(aadhaarNumber);
    const safeAddress = normalizeStringField(address);
    const safeWard = normalizeStringField(ward);

    console.log('[AUTH] Register request received for mobile:', safeMobile);

    const existingMobile = await User.findOne({ mobile: safeMobile });
    if (existingMobile) {
      return res.status(409).json({
        success: false,
        message: 'Mobile number is already registered.'
      });
    }

    if (safeEmail) {
      const existingEmail = await User.findOne({ email: safeEmail });
      if (existingEmail) {
        return res.status(409).json({
          success: false,
          message: 'Email is already registered.'
        });
      }
    }

    const user = await User.create({
      name: safeName,
      mobile: safeMobile,
      email: safeEmail || undefined,
      password,
      aadhaarNumber: safeAadhaar || undefined,
      address: safeAddress || undefined,
      ward: safeWard || undefined,
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
    logAuthError('Registration error', error);
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
    const safeMobile = normalizeStringField(mobile);
    const safeEmail = normalizeStringField(email, { lower: true });

    console.log('[AUTH] Login request received:', {
      mobile: safeMobile || null,
      email: safeEmail || null
    });

    const query = {};

    if (safeEmail) {
      query.email = safeEmail;
    } else {
      query.mobile = safeMobile;
    }

    const user = await User.findOne(query).select('+password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.'
      });
    }

    if (safeEmail && user.role !== 'admin') {
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
    logAuthError('Login error', error);
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
    logAuthError('Logout error', error);
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
    logAuthError('Get current user error', error);
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
    logAuthError('Change password error', error);
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
