const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: function() {
      // Password is required only if not using Google OAuth
      return !this.googleId;
    }
  },
  roles: {
    type: [String],
    enum: ["farmer", "retailer", "admin"],
    default: [],
    required: true,
    validate: {
      validator: function(v) {
        return v && v.length > 0;
      },
      message: 'User must have at least one role'
    }
  },
  activeRole: {
    type: String,
    enum: ["farmer", "retailer", "admin"],
    required: true
  },
  // Google OAuth fields
  googleId: {
    type: String,
    unique: true,
    sparse: true // Allows null values while maintaining uniqueness
  },
  profilePicture: {
    type: String,
    default: ""
  },
  authProvider: {
    type: String,
    enum: ["local", "google"],
    default: "local"
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  }
});

// Index for faster email lookups
UserSchema.index({ email: 1 });
UserSchema.index({ googleId: 1 });

module.exports = mongoose.model("User", UserSchema);