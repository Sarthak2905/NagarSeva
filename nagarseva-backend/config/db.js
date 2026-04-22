const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const mongoUri = process.env.MONGODB_URI;

    if (!mongoUri) {
      console.log('[DB] MONGODB_URI is missing in environment variables.');
      throw new Error('MONGODB_URI is required');
    }

    const connection = await mongoose.connect(mongoUri);
    console.log(`[DB] MongoDB connected: ${connection.connection.host}`);
  } catch (error) {
    console.log('[DB] MongoDB connection failed:', error.message);
    process.exit(1);
  }
};

module.exports = connectDB;
