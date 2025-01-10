const bcrypt = require('bcrypt');
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');
const jwt = require('jsonwebtoken');


let otpStore = {};

// Request OTP 
exports.requestOTP = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if the email is already registered
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
        otpStore[email] = { otp, timestamp: Date.now() };

        await sendEmail(email, 'OTP Verification', `Your OTP is: ${otp}`);

        res.status(200).json({ message: 'OTP sent to email.' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Verify OTP and register user
exports.verifyOTP = async (req, res) => {
    try {
        const { username, email, password, otp } = req.body;

        const storedOTP = otpStore[email];
        if (!storedOTP || storedOTP.otp !== otp) {
            return res.status(400).json({ error: 'Invalid or expired OTP.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({ username, email, password: hashedPassword });
        await user.save();

        delete otpStore[email]; 

        res.status(201).json({ message: 'Registration successful.' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};



exports.login = async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Return user details along with the token
        res.status(200).json({
            message: 'Login successful',
            user: { username: user.username, email: user.email }, // Include user details
            token,
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};



exports.requestPasswordResetOTP = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate 6-digit OTP
        otpStore[email] = { otp, timestamp: Date.now() };

        await sendEmail(email, 'Password Reset OTP', `Your OTP for password reset is: ${otp}`);

        res.status(200).json({ message: 'OTP sent to email.' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Reset Password
exports.resetPassword = async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        const storedOTP = otpStore[email];
        if (!storedOTP || storedOTP.otp !== otp) {
            return res.status(400).json({ error: 'Invalid or expired OTP.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await User.updateOne({ email }, { password: hashedPassword });

        delete otpStore[email]; // Clear OTP after successful reset

        res.status(200).json({ message: 'Password reset successful.' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
