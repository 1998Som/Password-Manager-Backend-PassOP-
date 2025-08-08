const express = require("express");

const dotenv = require("dotenv");
const { MongoClient } = require("mongodb");

const bodyParser = require("body-parser");
const cors = require("cors");

dotenv.config();

// or as an es module:
// import { MongoClient } from 'mongodb'

// Connection URL
const url = process.env.MONGO_URI;

const client = new MongoClient(url);

// Database Name
const dbName = "passop";
const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cors());
client
  .connect()
  .then(() => {
    console.log("✅ MongoDB connected");
    app.listen(port, () => {
      console.log(`✅ Server is running on port  http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err);
  });
//get a password
app.get("/", async (req, res) => {
  const db = client.db(dbName);
  const collection = db.collection("passwords");
  const findResult = await collection.find({}).toArray();
  res.json(findResult);
});
// save a password
app.post("/", async (req, res) => {
  const password = req.body;
  const db = client.db(dbName);
  const collection = db.collection("passwords");
  const findResult = await collection.insertOne(password);
  res.send({
    success: true,
    result: findResult,
    message: "password saved successfully",
  });
});
//delete a password
const { ObjectId } = require("mongodb");

app.delete("/", async (req, res) => {
  try {
    const { _id } = req.body;

    // Check if ID exists and is valid
    if (!_id || !ObjectId.isValid(_id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid or missing _id for deletion",
      });
    }

    const db = client.db(dbName);
    const collection = db.collection("passwords");

    const result = await collection.deleteOne({ _id: new ObjectId(_id) });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Password not found" });
    }

    res.json({
      success: true,
      message: "Password deleted successfully",
    });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// update a password
app.put("/", async (req, res) => {
  try {
    const { _id, website, username, password } = req.body;

    if (!_id || !ObjectId.isValid(_id)) {
      return res.status(400).json({ success: false, message: "Invalid ID" });
    }

    const db = client.db(dbName);
    const collection = db.collection("passwords");

    const result = await collection.updateOne(
      { _id: new ObjectId(_id) },
      { $set: { website, username, password } }
    );

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Password not found" });
    }

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("Update error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Only export app for testing, otherwise start server if run directly
if (require.main === module) {
  // Already handled by client.connect().then(...)
} else {
  module.exports = app;
}
