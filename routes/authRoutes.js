const express = require('express');
const {
    requestOTP,
    verifyOTP,
    login,
    requestPasswordResetOTP,
    resetPassword,
} = require('../controllers/authController');

const router = express.Router();

router.post('/register', requestOTP);
router.post('/verify-otp', verifyOTP);
router.post('/login', login);
router.post('/request-password-reset-otp', requestPasswordResetOTP);
router.post('/reset-password', resetPassword);

module.exports = router;
