import blacklistTokenModel from '../models/blacklistTokenModel.js';
import userModel from '../models/userModel.js';
import jwt from 'jsonwebtoken';


const authUser = async (req, res, next) => {
    const token = req.cookie.token || req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Not authenticated' });
    }

    const isBlacklisted = await blacklistTokenModel.findOne({ token: token });
    if (isBlacklisted) {
        return res.status(401).json({ message: 'Authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'kaku');
        const user = await userModel.findById(decoded._id);

        req.user = user;
        return next();
    } catch (error) {
        console.error(error);
        return res.status(401).json({ message: 'Authorization denied' });
    }
};
const authMiddleware = {
    authUser
}


export default authMiddleware;