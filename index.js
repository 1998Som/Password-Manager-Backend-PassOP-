const express = require("express");


const dotenv = require("dotenv");
const { MongoClient } = require("mongodb");
const bodyparser = require("body-parser");
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
client.connect()
  .then(() => {
    console.log("✅ MongoDB connected");
    app.listen(port, () => {
      console.log(`✅ Server is running on port ${port}`);
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
app.delete("/", async (req, res) => {
  const password = req.body;
  const db = client.db(dbName);
  const collection = db.collection("passwords");
  const findResult = await collection.deleteOne(password);
  res.send({
    success: true,
    result: findResult,
    message: "password deleted successfully",
  });
});
// update a password
app.put("/", async (req, res) => {
  try {
    const { id, site, username, password } = req.body;

    if (!id || !site || !username || !password) {
      return res.status(400).json({ success: false, message: "Invalid data" });
    }

    const db = client.db(dbName);
    const collection = db.collection("passwords");

    const result = await collection.updateOne(
      { id }, // match by custom UUID
      { $set: { site, username, password } } // update fields
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "Not found" });
    }

    res.json({
      success: true,
      result,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Update error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


module.exports = app;