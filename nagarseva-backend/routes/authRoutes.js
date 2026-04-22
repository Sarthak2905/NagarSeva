const express = require('express');
const { body } = require('express-validator');
const {
  register,
  login,
  logout,
  getCurrentUser,
  changePassword
} = require('../controllers/authController');
const { protectRoute } = require('../middleware/authMiddleware');

const router = express.Router();

const registerValidation = [
  body('name').isString().withMessage('Name must be text.').trim().notEmpty().withMessage('Name is required.'),
  body('mobile')
    .isString()
    .withMessage('Mobile must be text.')
    .trim()
    .matches(/^[0-9]{10}$/)
    .withMessage('Valid 10 digit mobile number is required.'),
  body('email')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('Email must be text.')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required.'),
  body('password')
    .isString()
    .withMessage('Password must be text.')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters.'),
  body('aadhaarNumber')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('Aadhaar number must be text.')
    .matches(/^[0-9]{12}$/)
    .withMessage('Aadhaar number must be 12 digits.'),
  body('address')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('Address must be text.')
    .isLength({ min: 5 })
    .withMessage('Address must be at least 5 characters.'),
  body('ward')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('Ward must be text.')
    .isLength({ min: 1 })
    .withMessage('Ward is required when provided.')
];

const loginValidation = [
  body('password').isString().withMessage('Password must be text.').notEmpty().withMessage('Password is required.'),
  body('mobile')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('Mobile must be text.')
    .matches(/^[0-9]{10}$/)
    .withMessage('Mobile must be 10 digits.'),
  body('email')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('Email must be text.')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required.'),
  body().custom((value) => {
    if (!value.mobile && !value.email) {
      throw new Error('Either mobile or email is required for login.');
    }

    return true;
  })
];

const changePasswordValidation = [
  body('currentPassword').isString().withMessage('Current password must be text.').notEmpty().withMessage('Current password is required.'),
  body('newPassword')
    .isString()
    .withMessage('New password must be text.')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters.')
];

router.post('/register', registerValidation, register);
router.post('/login', loginValidation, login);
router.post('/logout', protectRoute, logout);
router.get('/me', protectRoute, getCurrentUser);
router.patch('/change-password', protectRoute, changePasswordValidation, changePassword);

module.exports = router;
