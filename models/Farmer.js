const mongoose = require("mongoose");

const ProduceSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  qty: {
    type: String,
    required: true,
    trim: true
  },
  price: {
    type: String,
    required: true,
    trim: true
  },
  photo: {
    type: String,  // Base64 encoded image
    default: ""
  }
});

const FarmerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  contact: {
    type: String,
    trim: true,
    default: ""
  },
  location: {
    type: String,
    trim: true,
    default: ""
  },
  produce: [ProduceSchema],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt timestamp before saving
FarmerSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Index for faster userId lookups
FarmerSchema.index({ userId: 1 });

module.exports = mongoose.model("Farmer", FarmerSchema);