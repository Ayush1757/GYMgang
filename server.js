require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const fs = require("fs");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const app = express();

app.use(helmet({
    contentSecurityPolicy: false, // Disabled to allow external CDNs (Tailwind, Chart.js, etc.)
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

mongoose.connect(process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/loginDB")
.then(() => console.log("MongoDB Connected"))
.catch(err => console.error("MongoDB Connection Error:", err));


/* ================= USER SCHEMA ================= */

const userSchema = new mongoose.Schema({
    fullname: String,
    email: String,
    password: String,
    role: { type: String, default: "user" },
    expiry: String,
    qrImage: String   // uploaded QR image path
});

const User = mongoose.model("User", userSchema);


/* ================= ATTENDANCE SCHEMA ================= */

const attendanceSchema = new mongoose.Schema({
    email: String,
    memberName: String,
    date: String,
    checkInTime: String,
    createdAt: { type: Date, default: Date.now }
});

const Attendance = mongoose.model("Attendance", attendanceSchema);


/* ================= CLOUDINARY CONFIG ================= */

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: "gym-qr-codes",
        allowed_formats: ["jpg", "png", "jpeg"],
    },
});

const upload = multer({ storage });


/* ================= AUTH MIDDLEWARE ================= */

async function authenticate(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).send("Unauthorized: Please login first");

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie("token");
        return res.status(401).send("Unauthorized: Invalid session");
    }
}

async function ensureAdmin(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ success: false, message: "No token provided" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== "admin") {
            return res.status(403).json({ success: false, message: "Not authorised" });
        }
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie("token");
        return res.status(401).json({ success: false, message: "Invalid token" });
    }
}


/* ================= REGISTER ================= */

app.post("/register", async (req, res) => {
    try {
        const { fullname, email, password, confirmPassword, role, adminKey } = req.body;

        if (password !== confirmPassword)
            return res.send("Passwords do not match");

        if (role === "admin") {
            if (adminKey !== process.env.ADMIN_KEY)
                return res.send("Invalid Admin Key");
        }

        const existing = await User.findOne({ email });
        if (existing)
            return res.send("Email already registered");

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            fullname,
            email,
            password: hashedPassword,
            role: role || "user"
        });

        await newUser.save();
        res.redirect("/login.html");

    } catch (err) {
        res.send("Error registering user: " + err.message);
    }
});


/* ================= LOGIN ================= */

app.post("/login", async (req, res) => {
    try {
        const { email, password, role } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.send("User not found");

        if (role && user.role !== role)
            return res.send("Incorrect role selected");

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.send("Invalid Password");

        // Create JWT Token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "24h" }
        );

        // Set secure cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", // Secure in production
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        const safeUser = {
            fullname: user.fullname,
            email: user.email,
            role: user.role
        };

        const redirect = user.role === "admin"
            ? "/dashboard.html"
            : "/home.html";

        res.send(`
            <script>
                localStorage.setItem("user", '${JSON.stringify(safeUser)}');
                window.location.href = "${redirect}";
            </script>
        `);

    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).send("Login error");
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/login.html");
});


/* ================= ADMIN UPLOAD QR ================= */

app.post("/uploadQR", authenticate, ensureAdmin, upload.single("qrImage"), async (req, res) => {
    try {
        const { memberEmail } = req.body;

        const user = await User.findOne({ email: memberEmail });
        if (!user) {
            return res.json({ success: false, message: "Member not found" });
        }

        user.qrImage = req.file.path; // This is the Cloudinary URL
        await user.save();

        res.json({ success: true, message: "QR uploaded successfully" });

    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});


/* ================= GET MEMBER QR ================= */

app.get("/getMemberQR", authenticate, async (req, res) => {
    const email = req.user.email; // Use email from token for security

    const user = await User.findOne({ email });

    if (!user || !user.qrImage) {
        return res.json({ success: false });
    }

    res.json({
        success: true,
        qrImage: user.qrImage
    });
});


/* ================= SCAN MEMBER QR ================= */

app.post("/scanMemberQR", authenticate, ensureAdmin, async (req, res) => {
    try {
        const { scannedData } = req.body;

        const user = await User.findOne({ email: scannedData });
        if (!user) {
            return res.json({ success: false, message: "Invalid QR" });
        }

        const now = new Date();
        const today = now.toISOString().split("T")[0];
        const time = now.toLocaleTimeString();

        const existing = await Attendance.findOne({
            email: user.email,
            date: today
        });

        if (existing) {
            return res.json({ success: false, message: "Already marked today" });
        }

        await Attendance.create({
            email: user.email,
            memberName: user.fullname,
            date: today,
            checkInTime: time
        });

        res.json({
            success: true,
            message: "Attendance marked for " + user.fullname
        });

    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});


/* ================= DASHBOARD STATS ================= */

app.get("/getDashboardStats", authenticate, async (req, res) => {
    try {
        const today = new Date().toISOString().split("T")[0];

        const totalMembers = await User.countDocuments({ role: "user" });
        const todaysAttendance = await Attendance.countDocuments({ date: today });

        res.json({ totalMembers, todaysAttendance });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


/* ================= SERVER ================= */

if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Gym app running on http://localhost:${PORT}`);
    });
}

module.exports = app;