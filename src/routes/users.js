import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { UserModel } from "../models/Users.js";

const router = express.Router();

// User Registration Route
router.post("/register", async (req, res) => {
  try {
    // Extract email, username, and password from the request body
    const { email, username, password } = req.body;

    // Validate input fields
    if (!email || !username || !password) {
      return res.status(400).json({ message: "All fields are required!" });
    }

    // Check if a user with the same username already exists
    const existingUser = await UserModel.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists!" });
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user with the hashed password and save it to the database
    const newUser = new UserModel({
      email,
      username,
      password: hashedPassword,
    });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Error in /register route:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// User Login Route
router.post("/login", async (req, res) => {
  try {
    // Extract username and password from the request body
    const { username, password } = req.body;

    // Validate input fields
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username and password are required!" });
    }

    // Find the user with the provided username
    const user = await UserModel.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: "User does not exist!" });
    }

    // Compare the provided password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid username or password!" });
    }

    // If the password is valid, create a JWT token and send it as a response
    const token = jwt.sign({ id: user._id }, "secret", { expiresIn: "1h" });
    res.status(200).json({ token, userID: user._id });
  } catch (error) {
    console.error("Error in /login route:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Middleware for verifying JWT tokens
export const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Extract Bearer token
  if (!token) {
    return res.status(401).json({ message: "Authorization token is missing" });
  }

  jwt.verify(token, "secret", (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = decoded;
    next();
  });
};

export { router as userRouter };
