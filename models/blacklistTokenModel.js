import mongoose from 'mongoose';

const blacklistTokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true
    },
    createdAt: {
        type: Date,
        required: true,
        default: Date.now,
        expires: 86400
    }
});

const blacklistTokenModel = mongoose.model('blacklistTokenModel', blacklistTokenSchema);

export default blacklistTokenModel;
