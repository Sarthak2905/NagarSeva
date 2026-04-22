const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true
  },
  mobile: {
    type: String,
    required: [true, 'Mobile number is required'],
    unique: true,
    trim: true
  },
  email: {
    type: String,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: 6,
    select: false
  },
  aadhaarNumber: {
    type: String,
    trim: true
  },
  address: {
    type: String,
    trim: true
  },
  ward: {
    type: String,
    trim: true
  },
  role: {
    type: String,
    enum: ['citizen', 'admin', 'wardLeader'],
    default: 'citizen'
  },
  profilePhoto: {
    type: String,
    trim: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function hashPassword(next) {
  try {
    if (!this.isModified('password')) {
      return next();
    }

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    return next();
  } catch (error) {
    return next(error);
  }
});

userSchema.methods.comparePassword = async function comparePassword(enteredPassword) {
  return bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.generateJwt = function generateJwt() {
  return jwt.sign(
    {
      id: this._id,
      role: this.role
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRE || '7d'
    }
  );
};

userSchema.methods.toSafeObject = function toSafeObject() {
  const userObject = this.toObject({ getters: true });
  delete userObject.password;

  if (userObject.aadhaarNumber) {
    const digitsOnly = String(userObject.aadhaarNumber).replace(/\D/g, '');
    userObject.aadhaarNumber = digitsOnly.length >= 4
      ? `XXXXXXXX${digitsOnly.slice(-4)}`
      : 'XXXXXXXX';
  }

  return userObject;
};

module.exports = mongoose.model('User', userSchema);
