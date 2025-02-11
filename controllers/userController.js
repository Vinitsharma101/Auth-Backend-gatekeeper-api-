import userModel from '../models/userModel.js';
import userService from '../services/userService.js';
import { validationResult } from 'express-validator';
import blacklistTokenModel from '../models/blacklistTokenModel.js';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();


// Store OTPs temporarily (in production, consider using Redis)
const otpStore = new Map();


// Create NodeMailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Generate OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const registerUser = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    const isUserAlreadyExists = await userModel.findOne({ email: email });
    if (isUserAlreadyExists) {
        return res.status(400).json({ message: 'User with this email already exists' });
    }

    try {
        const hashedPassword = await userModel.hashPassword(password);
        const newUser = await userService.registerUser({
            username,
            email,
            password: hashedPassword
        });

        const token = newUser.generateAuthToken();
        res.status(201).json({ user: newUser, token });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error registering user');
    }
};

const loginUser = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Please provide email and password' });
    }
    const user = await userModel.findOne({ email }).select('+password');
    if (!user) {
        return res.status(400).send('Invalid email or password');
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
        return res.status(400).send('Invalid email or password');
    }

    const token = user.generateAuthToken();
    res.cookie('token', token);
    res.status(200).json({ user, token });
};



const logoutUser = async (req, res, next) => {
    res.clearCookie('token');
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    await blacklistTokenModel.create({ token });
    res.status(200).send('Logged out');
};

const refreshToken = async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token not found' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || 'kaku');
        const user = await userModel.findById(decoded._id);
        const newAccessToken = user.generateAuthToken();

        res.cookie('token', newAccessToken);
        res.json({ token: newAccessToken });
    } catch (error) {
        res.status(401).json({ message: 'Invalid refresh token' });
    }
};


// Controller for initiating forgot password
const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found with this email'
            });
        }

        // Generate OTP
        const otp = generateOTP();

        // Store OTP with expiration (5 minutes)
        otpStore.set(email, {
            otp,
            expiry: Date.now() + 5 * 60 * 1000
        });

        // Send email
        const mailOptions = {
            from: process.env.EMAIL_USERNAME,
            to: email,
            subject: 'Password Reset OTP',
            text: `Your OTP for password reset is: ${otp}. This OTP will expire in 5 minutes.`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({
            success: true,
            message: 'OTP sent successfully to your email'
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Error in sending OTP'
        });
    }
};

// Controller for verifying OTP and updating password
const verifyOTPAndResetPassword = async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        const storedOTPData = otpStore.get(email);

        if (!storedOTPData) {
            return res.status(400).json({ message: 'OTP expired or not found' });
        }

        if (Date.now() > storedOTPData.expiry) {
            otpStore.delete(email);
            return res.status(400).json({ message: 'OTP has expired' });
        }

        if (storedOTPData.otp !== otp) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        // Hash new password
        const hashedPassword = await userModel.hashPassword(newPassword);

        // Update password
        await userModel.findOneAndUpdate(
            { email },
            { password: hashedPassword }
        );

        // Clear OTP
        otpStore.delete(email);

        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error in reset password process' });
    }
};

module.exports = {
    forgotPassword,
    verifyOTPAndResetPassword
};



// Export all functions together as a default export
const userController = {
    registerUser,
    loginUser,
    logoutUser,
    refreshToken,
    forgotPassword
};

export default userController;
