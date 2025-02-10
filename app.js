import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import userRouter from './Routes/userRouter.js';
import dotenv from "dotenv";
import connectToDB from "./db/db.js";
dotenv.config();


connectToDB();


const app = express();


app.use(express.json());
app.use(cors(
    {
        origin: process.env.FRONTEND_URL,
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        allowedHeaders: ['Content-Type', 'Authorization']
    }
));
app.use(cookieParser());

app.get("/", (req, res) => {
    res.send("Server is running!");
});

app.use('/api/users', userRouter);

export default app;
