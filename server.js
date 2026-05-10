const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const User = require("./userModel");

const app = express();

app.use(express.json());


// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));


// ================= REGISTER =================
app.post("/register", async (req, res) => {

    const { email, password } = req.body;

    // Check User
    const oldUser = await User.findOne({ email });

    if (oldUser) {
        return res.json({
            message: "User Already Exists"
        });
    }

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save User
    const user = new User({
        email,
        password: hashedPassword
    });

    await user.save();

    res.json({
        message: "Registration Successful"
    });
});


// ================= LOGIN =================
app.post("/login", async (req, res) => {

    const { email, password } = req.body;

    // Find User
    const user = await User.findOne({ email });

    if (!user) {
        return res.json({
            message: "User Not Found"
        });
    }

    // Compare Password
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
        return res.json({
            message: "Invalid Password"
        });
    }

    // Generate Token
    const token = jwt.sign(
        { id: user._id },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.json({
        message: "Login Successful",
        token
    });
});


// ================= PROTECTED ROUTE =================
app.get("/profile", verifyToken, (req, res) => {

    res.json({
        message: "Protected Profile Data",
        user: req.user
    });
});


// ================= VERIFY TOKEN =================
function verifyToken(req, res, next) {

    const header = req.header("Authorization");

    if (!header) {
        return res.json({
            message: "Access Denied"
        });
    }

    try {

        const token = header.replace("Bearer ", "");

        const verified = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.user = verified;

        next();

    } catch (err) {

        res.json({
            message: "Invalid Token"
        });
    }
}


// ================= SERVER =================
app.listen(5000, () => {
    console.log("Server Running on Port 5000");
});