const mongoose = require("mongoose");

const OrderItemSchema = new mongoose.Schema({
  produceName: {
    type: String,
    required: true
  },
  quantity: {
    type: Number,  // Changed to Number for quantity calculation
    required: true
  },
  price: {
    type: String,
    required: true
  }
});

const OrderSchema = new mongoose.Schema({
  retailerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  retailerName: {
    type: String,
    required: true
  },
  retailerContact: {
    type: String,
    required: true
  },
  farmerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Farmer",
    required: true
  },
  farmerName: {
    type: String,
    required: true
  },
  farmerContact: {
    type: String,
    default: ""
  },
  items: [OrderItemSchema],
  totalAmount: {
    type: Number,
    required: true
  },
  deliveryAddress: {
    type: String,
    required: true
  },
  contactNumber: {
    type: String,
    required: true
  },
  courierService: {
    type: String,
    enum: ["standard", "express", "farmer-choice"],
    default: "standard"
  },
  paymentMethod: {
    type: String,
    enum: ["upi", "cod"],
    required: true
  },
  upiTransactionId: {
    type: String,
    default: ""
  },
  status: {
    type: String,
    enum: ["pending", "confirmed", "delivered", "cancelled"],
    default: "pending"
  },
  orderDate: {
    type: Date,
    default: Date.now
  },
  confirmedAt: Date,
  deliveredAt: Date,
  cancelledAt: Date,
  notes: {
    type: String,
    default: ""
  }
});

// Update timestamps when status changes
OrderSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    if (this.status === 'confirmed' && !this.confirmedAt) {
      this.confirmedAt = new Date();
    } else if (this.status === 'delivered' && !this.deliveredAt) {
      this.deliveredAt = new Date();
    } else if (this.status === 'cancelled' && !this.cancelledAt) {
      this.cancelledAt = new Date();
    }
  }
  next();
});

// Index for faster queries
OrderSchema.index({ retailerId: 1, orderDate: -1 });
OrderSchema.index({ farmerId: 1, orderDate: -1 });
OrderSchema.index({ status: 1 });

module.exports = mongoose.model("Order", OrderSchema);