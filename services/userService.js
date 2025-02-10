import userModel from '../models/userModel.js';

export const registerUser = async ({
    username,

    email,
    password
}) => {
    if (!username || !email || !password) {
        throw new Error('All fields are required');
    }
    const user = await userModel.create({
        username,
        email,
        password
    });
    return user;
};

const userService = {
    registerUser
}
export default userService;