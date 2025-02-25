import express from 'express';
import { body } from 'express-validator';
import authMiddleware from '../middlewares/auth.middleware.js';
import userController from '../controllers/userController.js';
import { loginLimiter } from '../middlewares/rateLimiter.js';
const {
    forgotPassword,
    verifyOTPAndResetPassword
} = require('../controllers/userController.js');

const router = express.Router();
router.post('/register',
    [
        body('username').notEmpty().withMessage('Username is required'),
        body('email').isEmail().withMessage('Please enter a valid email'),
        body('password').isLength({ min: 4 }).withMessage('Password must be at least 8 characters long')
    ],
    userController.registerUser
)
router.post('/login', loginLimiter, [
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
], userController.loginUser)

router.get('/logout', authMiddleware.authUser, userController.logoutUser)
router.post('/refresh-token', userController.refreshToken)
// router.post('/verify-email/:token', userController.verifyEmail)

router.post('/forgot-password', [
    body('email').isEmail().withMessage('Please enter a valid email')
], forgotPassword);

router.post('/reset-password', [
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('Invalid OTP'),
    body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
], verifyOTPAndResetPassword);

export default router;
	