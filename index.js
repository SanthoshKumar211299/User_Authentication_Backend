import express from 'express'
import dotenv from 'dotenv'
import mongoose from 'mongoose';
import cors from 'cors'

import cookieParser from 'cookie-parser';
import { UserRouter } from './routes/User.js';
dotenv.config();

const app=express()

app.use(cors({
    origin: 'http://localhost:5173', // Allow only this origin
    credentials: true     ,
    methods: ["get", "post", "put", "delete"],           // Allow credentials
}
));
app.use(cookieParser())
app.use(express.json())
app.use('/auth', UserRouter)

mongoose.connect("mongodb+srv://subjansan:dUWtOxGhuCKnyVGF@cluster0.zreu9.mongodb.net/Authentication")


app.listen(process.env.PORT,()=>{
    console.log("Server is Running");

})