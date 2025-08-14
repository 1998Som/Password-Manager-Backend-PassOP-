const express = require("express");
const dotenv = require("dotenv");
const { MongoClient, ObjectId } = require("mongodb");
const bodyParser = require("body-parser");
const cors = require("cors");

dotenv.config();

const url = process.env.MONGO_URI;
const client = new MongoClient(url);
const dbName = "passop";
const app = express();
const port = process.env.PORT || 3000;

// Configure CORS with specific options
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'https://password-manager-pass-op.vercel.app',
      'https://password-manager-pass-op-zeta.vercel.app'
    ];
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('Blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-User-Id', 'Authorization', 'user-id'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  maxAge: 86400,  // Preflight results can be cached for 24 hours
  optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
};

app.use(bodyParser.json());
app.use(cors(corsOptions));

// Middleware to verify user authentication
const requireAuth = async (req, res, next) => {
  const userId = req.headers['x-user-id'];
  
  if (!userId) {
    console.error('No user ID provided in request');
    return res.status(401).json({ 
      success: false, 
      message: "Authentication required" 
    });
  }

  console.log('Request authenticated for user:', userId);
  req.userId = userId; // Attach userId to request object
  next();
};

// Connect to MongoDB
client.connect()
  .then(() => {
    console.log("✅ MongoDB connected");
    app.listen(port, () => {
      console.log(`✅ Server is running on port http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err);
  });

// Get passwords for authenticated user
app.get("/", requireAuth, async (req, res) => {
  try {
    const db = client.db(dbName);
    const collection = db.collection("passwords");
    
    console.log('Fetching passwords for user:', req.userId);
    
    // Ensure index exists for userId
    await collection.createIndex({ userId: 1 });
    
    // Only fetch passwords for the authenticated user
    const findResult = await collection.find({ 
      userId: req.userId 
    }).toArray();
    
    console.log(`Found ${findResult.length} passwords for user ${req.userId}`);
    
    // Keep userId in the response
    res.json(findResult);
  } catch (error) {
    console.error("Get passwords error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to fetch passwords" 
    });
  }
});

// Save password for authenticated user
app.post("/", requireAuth, async (req, res) => {
  try {
    const { site, username, password } = req.body;

    // Validate required fields
    if (!site || !username || !password) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields"
      });
    }

    const db = client.db(dbName);
    const collection = db.collection("passwords");

    // Create new password document with user ID
    const newPassword = {
      site,
      username,
      password,
      userId: req.userId,
      createdAt: new Date()
    };

    const result = await collection.insertOne(newPassword);
    
    console.log(`Password saved for user ${req.userId}`);
    
    res.status(201).json({
      success: true,
      result: {
        _id: result.insertedId
      },
      message: "Password saved successfully"
    });
  } catch (error) {
    console.error("Save password error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to save password" 
    });
  }
});

// Delete password for authenticated user
app.delete("/", requireAuth, async (req, res) => {
  try {
    const { _id } = req.body;

    // Validate that we have an ID
    if (!_id) {
      return res.status(400).json({
        success: false,
        message: "Password ID is required"
      });
    }

    const db = client.db(dbName);
    const collection = db.collection("passwords");

    // First verify the password belongs to the user
    const query = { userId: req.userId };
    if (ObjectId.isValid(_id)) {
      query._id = new ObjectId(_id);
    } else {
      query._id = _id;
    }

    const password = await collection.findOne(query);

    if (!password) {
      return res.status(404).json({
        success: false,
        message: "Password not found"
      });
    }

    if (password.userId !== req.userId) {
      console.error(`Unauthorized deletion attempt of password ${_id} by user ${req.userId}`);
      return res.status(403).json({
        success: false,
        message: "You don't have permission to delete this password"
      });
    }

    // Delete the password using the same query
    const result = await collection.deleteOne(query);

    if (result.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Password not found"
      });
    }

    res.json({
      success: true,
      message: "Password deleted successfully"
    });
  } catch (error) {
    console.error("Delete password error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to delete password" 
    });
  }
});

// Update password for authenticated user
app.put("/", requireAuth, async (req, res) => {
  try {
    const { _id, site, username, password } = req.body;

    // Validate inputs
    if (!_id || !ObjectId.isValid(_id)) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid password ID" 
      });
    }

    if (!site || !username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields" 
      });
    }

    const db = client.db(dbName);
    const collection = db.collection("passwords");

    // First verify the password belongs to the user
    const existingPassword = await collection.findOne({
      _id: new ObjectId(_id)
    });

    if (!existingPassword) {
      return res.status(404).json({
        success: false,
        message: "Password not found"
      });
    }

    if (existingPassword.userId !== req.userId) {
      console.error(`Unauthorized update attempt of password ${_id} by user ${req.userId}`);
      return res.status(403).json({
        success: false,
        message: "You don't have permission to update this password"
      });
    }

    // Update the password
    const result = await collection.updateOne(
      { 
        _id: new ObjectId(_id), 
        userId: req.userId 
      },
      { 
        $set: { 
          site,
          username,
          password,
          updatedAt: new Date()
        } 
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ 
        success: false, 
        message: "Password not found" 
      });
    }

    res.json({
      success: true,
      message: "Password updated successfully"
    });
  } catch (error) {
    console.error("Update password error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to update password" 
    });
  }
});

// Export app for testing
module.exports = app;