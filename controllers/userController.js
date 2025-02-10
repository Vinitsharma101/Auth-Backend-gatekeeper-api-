import userModel from '../models/userModel.js';
import userService from '../services/userService.js';
import { validationResult } from 'express-validator';
import blacklistTokenModel from '../models/blacklistTokenModel.js';
import jwt from 'jsonwebtoken';


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
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await userModel.findById(decoded._id);
        const newAccessToken = user.generateAuthToken();

        res.cookie('token', newAccessToken);
        res.json({ token: newAccessToken });
    } catch (error) {
        res.status(401).json({ message: 'Invalid refresh token' });
    }
};



// Export all functions together as a default export
const userController = {
    registerUser,
    loginUser,
    logoutUser,
    refreshToken
};

export default userController;
