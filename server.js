require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const path = require("path");

const User = require("./models/User");
const Farmer = require("./models/Farmer");
const Order = require("./models/Order");

// Replace the middleware section in server.js (after const app = express();)
// This ensures proper order of middleware

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "farmdirect_secret_key";
const MONGO_URI = process.env.MONGO_URI;

// Google OAuth credentials from environment variables
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "https://farmdirect-backendd.onrender.com/auth/google/callback";

// Check if Google OAuth is properly configured
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn("⚠️  WARNING: Google OAuth credentials not configured!");
  console.warn("   Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env file");
  console.warn("   Google Sign-In will not work without these credentials");
}

// ✅ CRITICAL: Middleware must be in this exact order!

// 1. CORS - Must be first
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://farmdirect-rouge.vercel.app',
  'https://farmdirect-backendd.onrender.com'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn('⚠️ CORS blocked request from:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 2. Body parsers - MUST come before routes
app.use(express.json({ limit: '10mb' })); // ✅ Parse JSON bodies
app.use(express.urlencoded({ extended: true, limit: '10mb' })); // ✅ Parse URL-encoded bodies

// 3. Session middleware
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// 4. Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log("✅ MongoDB Atlas connected successfully");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google OAuth Strategy
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
      scope: ['profile', 'email']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('🔍 Google OAuth - Processing user:', profile.emails[0].value);
        
        let user = await User.findOne({ googleId: profile.id });

        if (user) {
          console.log('✅ Existing Google user found');
          return done(null, user);
        }

        user = await User.findOne({ email: profile.emails[0].value });

        if (user) {
          console.log('🔗 Linking Google account to existing user');
          user.googleId = profile.id;
          user.authProvider = "google";
          user.profilePicture = profile.photos[0]?.value || "";
          await user.save();
          return done(null, user);
        }

        console.log('✨ Creating new Google user');
        const newUser = new User({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.emails[0].value,
          profilePicture: profile.photos[0]?.value || "",
          authProvider: "google",
          roles: ["retailer"],
          activeRole: "retailer"
        });

        await newUser.save();
        console.log('✅ New user created successfully');
        done(null, newUser);
      } catch (err) {
        console.error('❌ Google OAuth error:', err);
        done(err, null);
      }
    }
  ));
}

// AUTH MIDDLEWARE
function auth(requiredRole) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = header.split(" ")[1];

    try {
      const decoded = jwt.verify(token, JWT_SECRET);

      if (requiredRole && !decoded.roles.includes(requiredRole)) {
        return res.status(403).json({ 
          error: "Forbidden: You don't have the required role",
          requiredRole,
          yourRoles: decoded.roles
        });
      }

      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}

// Root route
app.get("/", (req, res) => {
  res.json({
    message: "FarmDirect API v1.0 - Multi-Role Support",
    status: "running",
    googleAuth: GOOGLE_CLIENT_ID ? "configured" : "not configured",
    environment: process.env.NODE_ENV || "development"
  });
});

/* ==========================
   AUTH ROUTES
========================== */

app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: "All fields are required" });
    }

    if (!["farmer", "retailer", "both"].includes(role)) {
      return res.status(400).json({ error: "Invalid role. Choose: farmer, retailer, or both" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    let rolesArray = [];
    let activeRole = "";
    
    if (role === "both") {
      rolesArray = ["farmer", "retailer"];
      activeRole = "farmer";
    } else {
      rolesArray = [role];
      activeRole = role;
    }

    const user = new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      roles: rolesArray,
      activeRole: activeRole,
      authProvider: "local"
    });

    await user.save();

    if (rolesArray.includes("farmer")) {
      const farmer = new Farmer({
        userId: user._id,
        name: user.name,
        contact: "",
        location: "",
        produce: []
      });
      await farmer.save();
    }

    res.status(201).json({ 
      message: "User registered successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        roles: user.roles,
        activeRole: user.activeRole
      }
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Registration failed: " + err.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    if (user.authProvider === "google" && !user.password) {
      return res.status(401).json({ 
        error: "This account uses Google Sign-In. Please login with Google." 
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    if (!user.roles || user.roles.length === 0) {
      return res.status(400).json({ 
        error: "Account setup incomplete. Please contact support." 
      });
    }

    const token = jwt.sign(
      { 
        id: user._id, 
        roles: user.roles, 
        activeRole: user.activeRole,
        name: user.name 
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      roles: user.roles,
      activeRole: user.activeRole,
      role: user.activeRole,
      name: user.name,
      userId: user._id,
      profilePicture: user.profilePicture
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed: " + err.message });
  }
});

// Google OAuth routes
app.get("/auth/google", 
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { 
    failureRedirect: "https://farmdirect-rouge.vercel.app/login.html?error=google_auth_failed",
    session: true
  }),
  async (req, res) => {
    try {
      console.log('✅ Google callback successful for:', req.user.email);

      const token = jwt.sign(
        { 
          id: req.user._id, 
          roles: req.user.roles, 
          activeRole: req.user.activeRole,
          name: req.user.name 
        },
        JWT_SECRET,
        { expiresIn: "24h" }
      );

      if (!req.user.roles || req.user.roles.length === 0) {
        const redirectUrl = `https://farmdirect-rouge.vercel.app/role-selection.html?token=${token}&userId=${req.user._id}&name=${encodeURIComponent(req.user.name)}&email=${encodeURIComponent(req.user.email)}`;
        return res.redirect(redirectUrl);
      }

      const params = new URLSearchParams({
        token: token,
        roles: req.user.roles.join(','),
        activeRole: req.user.activeRole,
        role: req.user.activeRole,
        userId: req.user._id.toString(),
        name: req.user.name
      });

      const dashboardUrl = req.user.activeRole === "farmer" 
        ? `https://farmdirect-rouge.vercel.app/farmers.html?${params.toString()}`
        : `https://farmdirect-rouge.vercel.app/retailer.html?${params.toString()}`;

      res.redirect(dashboardUrl);

    } catch (error) {
      console.error('❌ Google callback error:', error);
      res.redirect('https://farmdirect-rouge.vercel.app/login.html?error=callback_failed');
    }
  }
);

app.post("/auth/set-roles", auth(), async (req, res) => {
  try {
    const { roles, activeRole } = req.body;

    if (!roles || !Array.isArray(roles) || roles.length === 0) {
      return res.status(400).json({ error: "At least one role is required" });
    }

    const validRoles = roles.filter(r => ["farmer", "retailer"].includes(r));
    if (validRoles.length === 0) {
      return res.status(400).json({ error: "Invalid roles" });
    }

    if (!activeRole || !validRoles.includes(activeRole)) {
      return res.status(400).json({ error: "Active role must be one of your roles" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.roles = validRoles;
    user.activeRole = activeRole;
    await user.save();

    if (validRoles.includes("farmer")) {
      const existingFarmer = await Farmer.findOne({ userId: user._id });
      if (!existingFarmer) {
        const farmer = new Farmer({
          userId: user._id,
          name: user.name,
          contact: "",
          location: "",
          produce: []
        });
        await farmer.save();
      }
    }

    const token = jwt.sign(
      { 
        id: user._id, 
        roles: user.roles, 
        activeRole: user.activeRole,
        name: user.name 
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Roles updated successfully",
      token,
      roles: user.roles,
      activeRole: user.activeRole,
      userId: user._id
    });
  } catch (err) {
    console.error("Role update error:", err);
    res.status(500).json({ error: "Failed to update roles: " + err.message });
  }
});

app.post("/auth/switch-role", auth(), async (req, res) => {
  try {
    const { activeRole } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (!user.roles.includes(activeRole)) {
      return res.status(400).json({ 
        error: `You don't have the ${activeRole} role. Your roles: ${user.roles.join(', ')}` 
      });
    }

    user.activeRole = activeRole;
    await user.save();

    const token = jwt.sign(
      { 
        id: user._id, 
        roles: user.roles, 
        activeRole: user.activeRole,
        name: user.name 
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: `Switched to ${activeRole} role`,
      token,
      roles: user.roles,
      activeRole: user.activeRole,
      userId: user._id
    });
  } catch (err) {
    console.error("Switch role error:", err);
    res.status(500).json({ error: "Failed to switch role: " + err.message });
  }
});

app.get("/auth/me", auth(), async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      roles: user.roles,
      activeRole: user.activeRole,
      profilePicture: user.profilePicture,
      authProvider: user.authProvider
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch user: " + err.message });
  }
});

app.post("/auth/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed" });
    }
    res.json({ message: "Logged out successfully" });
  });
});

/* ==========================
   FARMER ROUTES
========================== */

app.get("/farmers", async (req, res) => {
  try {
    const farmers = await Farmer.find().sort({ createdAt: -1 });
    res.json(farmers);
  } catch (err) {
    console.error("Error fetching farmers:", err);
    res.status(500).json({ error: "Failed to fetch farmers: " + err.message });
  }
});

app.get("/farmers/me", auth("farmer"), async (req, res) => {
  try {
    const farmer = await Farmer.findOne({ userId: req.user.id });
    if (!farmer) {
      return res.status(404).json({ error: "Farmer profile not found" });
    }
    res.json(farmer);
  } catch (err) {
    console.error("Error fetching farmer profile:", err);
    res.status(500).json({ error: "Failed to fetch profile: " + err.message });
  }
});

app.post("/farmers/profile", auth("farmer"), async (req, res) => {
  try {
    const { name, contact, location, produce } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: "Farm name is required" });
    }

    let farmer = await Farmer.findOne({ userId: req.user.id });

    if (farmer) {
      farmer.name = name.trim();
      farmer.contact = contact?.trim() || "";
      farmer.location = location?.trim() || "";
      farmer.produce = produce || [];
      await farmer.save();
    } else {
      farmer = new Farmer({
        userId: req.user.id,
        name: name.trim(),
        contact: contact?.trim() || "",
        location: location?.trim() || "",
        produce: produce || []
      });
      await farmer.save();
    }

    res.json({
      message: "Farmer profile saved successfully",
      farmer
    });
  } catch (err) {
    console.error("Error saving farmer profile:", err);
    res.status(500).json({ error: "Failed to save profile: " + err.message });
  }
});

app.put("/farmers/:id", auth("farmer"), async (req, res) => {
  try {
    const farmer = await Farmer.findById(req.params.id);
    
    if (!farmer) {
      return res.status(404).json({ error: "Farmer not found" });
    }

    if (farmer.userId.toString() !== req.user.id) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const updatedFarmer = await Farmer.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    res.json({
      message: "Farmer profile updated successfully",
      farmer: updatedFarmer
    });
  } catch (err) {
    console.error("Error updating farmer:", err);
    res.status(500).json({ error: "Failed to update: " + err.message });
  }
});

app.delete("/farmers/:id", auth("farmer"), async (req, res) => {
  try {
    const farmer = await Farmer.findById(req.params.id);
    
    if (!farmer) {
      return res.status(404).json({ error: "Farmer not found" });
    }

    if (farmer.userId.toString() !== req.user.id) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    await Farmer.findByIdAndDelete(req.params.id);
    
    res.json({ message: "Farmer profile deleted successfully" });
  } catch (err) {
    console.error("Error deleting farmer:", err);
    res.status(500).json({ error: "Failed to delete: " + err.message });
  }
});

/* ==========================
   ORDER ROUTES
========================== */

app.post("/orders", auth("retailer"), async (req, res) => {
  try {
    const { 
      farmerId, 
      farmerName,
      farmerContact,
      items, 
      totalAmount, 
      deliveryAddress,
      contactNumber,
      courierService,
      paymentMethod,
      upiTransactionId,
      notes 
    } = req.body;

    if (!farmerId || !items || !totalAmount || !deliveryAddress || !contactNumber || !paymentMethod) {
      return res.status(400).json({ 
        error: "All required fields must be provided" 
      });
    }

    const farmer = await Farmer.findById(farmerId);
    if (!farmer) {
      return res.status(404).json({ error: "Farmer not found" });
    }

    for (const orderItem of items) {
      const produce = farmer.produce.find(p => p.name === orderItem.produceName);
      
      if (!produce) {
        return res.status(400).json({ 
          error: `Product "${orderItem.produceName}" not found` 
        });
      }

      const availableQty = parseFloat(produce.qty) || 0;
      const orderedQty = parseFloat(orderItem.quantity) || 0;

      if (orderedQty > availableQty) {
        return res.status(400).json({ 
          error: `Insufficient quantity for "${orderItem.produceName}". Available: ${availableQty}, Requested: ${orderedQty}` 
        });
      }

      const newQty = availableQty - orderedQty;
      produce.qty = newQty > 0 ? newQty.toString() : "0 (Out of Stock)";
    }

    await farmer.save();

    const order = new Order({
      retailerId: req.user.id,
      retailerName: req.user.name,
      retailerContact: contactNumber,
      farmerId,
      farmerName: farmerName || farmer.name,
      farmerContact: farmerContact || farmer.contact,
      items: items.map(item => ({
        produceName: item.produceName,
        quantity: parseFloat(item.quantity),
        price: item.price
      })),
      totalAmount,
      deliveryAddress,
      contactNumber,
      courierService: courierService || "standard",
      paymentMethod,
      upiTransactionId: upiTransactionId || "",
      notes: notes || "",
      status: "pending"
    });

    await order.save();
    
    console.log(`📦 New order received!`);
    console.log(`   Order ID: ${order._id}`);
    console.log(`   Retailer: ${req.user.name} (${contactNumber})`);
    console.log(`   Farmer: ${farmerName}`);
    console.log(`   Total: ₹${totalAmount}`);
    console.log(`   Payment: ${paymentMethod.toUpperCase()}`);
    
    res.status(201).json({ 
      message: "Order placed successfully! Inventory updated.",
      order: {
        orderId: order._id,
        status: order.status,
        totalAmount: order.totalAmount,
        farmerName: order.farmerName,
        paymentMethod: order.paymentMethod
      }
    });
  } catch (err) {
    console.error("Error placing order:", err);
    res.status(500).json({ error: "Failed to place order: " + err.message });
  }
});

app.get("/orders/me", auth("retailer"), async (req, res) => {
  try {
    const orders = await Order.find({ retailerId: req.user.id })
      .sort({ orderDate: -1 });
    
    res.json(orders);
  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).json({ error: "Failed to fetch orders: " + err.message });
  }
});

app.get("/orders/farmer", auth("farmer"), async (req, res) => {
  try {
    const farmer = await Farmer.findOne({ userId: req.user.id });
    if (!farmer) {
      return res.status(404).json({ error: "Farmer profile not found" });
    }

    const orders = await Order.find({ farmerId: farmer._id })
      .sort({ orderDate: -1 });
    
    res.json(orders);
  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).json({ error: "Failed to fetch orders: " + err.message });
  }
});

app.put("/orders/:id/status", auth("farmer"), async (req, res) => {
  try {
    const { status } = req.body;

    if (!["pending", "confirmed", "delivered", "cancelled"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    const farmer = await Farmer.findOne({ userId: req.user.id });
    if (!farmer || order.farmerId.toString() !== farmer._id.toString()) {
      return res.status(403).json({ error: "Unauthorized: This order doesn't belong to you" });
    }

    if (status === 'cancelled' && order.status !== 'cancelled') {
      for (const orderItem of order.items) {
        const produce = farmer.produce.find(p => p.name === orderItem.produceName);
        if (produce) {
          const currentQty = parseFloat(produce.qty) || 0;
          const restoreQty = parseFloat(orderItem.quantity) || 0;
          produce.qty = (currentQty + restoreQty).toString();
        }
      }
      await farmer.save();
    }

    order.status = status;
    await order.save();
    
    res.json({
      message: `Order ${status} successfully`,
      order: {
        orderId: order._id,
        status: order.status,
        totalAmount: order.totalAmount
      }
    });
  } catch (err) {
    console.error("Error updating order status:", err);
    res.status(500).json({ error: "Failed to update order: " + err.message });
  }
});

app.get("/orders/:id", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (decoded.roles.includes("retailer") && order.retailerId.toString() === decoded.id) {
      return res.json(order);
    }

    if (decoded.roles.includes("farmer")) {
      const farmer = await Farmer.findOne({ userId: decoded.id });
      if (farmer && order.farmerId.toString() === farmer._id.toString()) {
        return res.json(order);
      }
    }

    return res.status(403).json({ error: "Unauthorized: You can only view your own orders" });
  } catch (err) {
    console.error("Error fetching order:", err);
    res.status(500).json({ error: "Failed to fetch order: " + err.message });
  }
});

/* ==========================
   ERROR HANDLING
========================== */

app.use((req, res) => {
  res.status(404).json({ 
    error: "Route not found",
    path: req.path
  });
});

app.use((err, req, res, next) => {
  console.error("Global error:", err);
  res.status(500).json({ 
    error: "Internal server error",
    message: err.message 
  });
});

/* ==========================
   START SERVER
========================== */

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════╗
║   🌾 FarmDirect Server Running 🌾    ║
╠═══════════════════════════════════════╣
║  Port: ${PORT}                           ║
║  Status: ✅ Active                     ║
║  Database: MongoDB Atlas              ║
║  Multi-Role: ✅ Enabled               ║
║  Orders: ✅ Enabled                    ║
║  Inventory: ✅ Tracking               ║
║  Google OAuth: ${GOOGLE_CLIENT_ID ? '✅' : '❌'} ${GOOGLE_CLIENT_ID ? 'Enabled' : 'Not Configured'}     ║
║  Environment: ${process.env.NODE_ENV || 'development'}              ║
╚═══════════════════════════════════════╝
  `);
});

process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await mongoose.connection.close();
  console.log('✅ MongoDB connection closed');
  process.exit(0);
});