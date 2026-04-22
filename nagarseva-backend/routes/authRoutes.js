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
  body('name').trim().notEmpty().withMessage('Name is required.'),
  body('mobile')
    .trim()
    .matches(/^[0-9]{10}$/)
    .withMessage('Valid 10 digit mobile number is required.'),
  body('email')
    .optional({ values: 'falsy' })
    .isEmail()
    .withMessage('Valid email is required.'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters.'),
  body('aadhaarNumber')
    .optional({ values: 'falsy' })
    .matches(/^[0-9]{12}$/)
    .withMessage('Aadhaar number must be 12 digits.'),
  body('address')
    .optional({ values: 'falsy' })
    .isLength({ min: 5 })
    .withMessage('Address must be at least 5 characters.'),
  body('ward')
    .optional({ values: 'falsy' })
    .isLength({ min: 1 })
    .withMessage('Ward is required when provided.')
];

const loginValidation = [
  body('password').notEmpty().withMessage('Password is required.'),
  body('mobile').optional({ values: 'falsy' }).matches(/^[0-9]{10}$/).withMessage('Mobile must be 10 digits.'),
  body('email').optional({ values: 'falsy' }).isEmail().withMessage('Valid email is required.'),
  body().custom((value) => {
    if (!value.mobile && !value.email) {
      throw new Error('Either mobile or email is required for login.');
    }

    return true;
  })
];

const changePasswordValidation = [
  body('currentPassword').notEmpty().withMessage('Current password is required.'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters.')
];

router.post('/register', registerValidation, register);
router.post('/login', loginValidation, login);
router.post('/logout', protectRoute, logout);
router.get('/me', protectRoute, getCurrentUser);
router.patch('/change-password', protectRoute, changePasswordValidation, changePassword);

module.exports = router;
