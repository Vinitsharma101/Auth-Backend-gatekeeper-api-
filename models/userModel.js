import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: {

        type: String,
        required: [true, "Username is required"],
        unique: true,
        trim: true
    },
    email: {
        type: String,
        required: [true, "Email is required"], 
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        // minlength: [6, "Password must be at least 6 characters"]
    }
}, {
    timestamps: true
});

userSchema.methods.generateAuthToken = function () {
    const token = jwt.sign(
        { _id: this._id },
        process.env.JWT_SECRET || 'kaku',
        { expiresIn: '24h' }
    );
    return token;
};

userSchema.methods.comparePassword = function (password) {
    return bcrypt.compare(password, this.password);
};


userSchema.statics.hashPassword = function (password) {
    return bcrypt.hash(password, 10);
};

const userModel = mongoose.model('user', userSchema);
export default userModel;