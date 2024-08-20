import express from 'express'
import bcrypt from 'bcryptjs'
import {User} from  '../models/User.js'
import jwt from 'jsonwebtoken'
import nodemailer from 'nodemailer'
import dotenv from "dotenv"

dotenv.config()
const router =express.Router();

router.post('/signup', async(req,res) => {
    const {username,email,password} =req.body;
    const user = await User.findOne({email})
    if(user){
        return res.json({message:"user already existed"})
    }
    const hashpassword = await bcrypt.hash(password, 10)
    const newUser =new User({
        username,
        email,
        password:hashpassword,

    })
    await newUser.save()
    return res.json({ status:true, message: " Record Registered "})
})

router.post('/login', async(req,res)=> {
    const {email,password} =req.body;
    const user =await User.findOne({email})
    if(!user){
        return res.json({message:"user is not registered"})
    }
    const validPassword =await bcrypt.compare(password,user.password)
    if(!validPassword){
        return res.json({message:"Wrong Password Entered!please enter again"})

    }
    const token = jwt.sign({username:user.username},process.env.KEY,{expiresIn: '1h'})
    res.cookie('token', token, { httpOnly:true, maxAge:360000})
    return res.json({ status:true, message:"Login successfully"})
})

router.post('/forgotPassword', async (req,res)=>{
    const {email} = req.body;
    try{
    const user = await User.findOne({email})
    console.log(user);
    if(!user){
        return res.json({message:"user is not registered"})
    }
    const token =jwt.sign({id: user._id},process.env.KEY,{expiresIn: '5m'})
    
    // Create the reset URL
    const resetUrl = `${process.env.CLIENT_URL}/resetPassword/${token}`;
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.NM_USER,
          pass: process.env.NM_PASSWORD,
        }
      });
      
      var mailOptions = {
        from: process.env.NM_USER,
        to: user.email,
        subject: 'Reset Password Request',
        html: `<p>You requested for a password reset</p>
        <p>Click this <a href="${resetUrl}">link</a> to reset your password</p>`,
      };
      
      transporter.sendMail(mailOptions, function(error, info){
        if (error) {
            return res.json({message:"error sending mail"})
        } else {
          return res.json({status:true,message:"mail sent"})
        }
      });

}catch(error){
    console.log(error);
}
})

router.post('/resetPassword/:token', async (req,res)=>{
    const {token} = req.params;
    const {password} = req.body;
    try {
        const decoded = await jwt.verify(token,process.env.KEY)
        const id = decoded.id;
        const hashPassword= await bcrypt.hash(password,10)
        await User.findByIdAndUpdate({_id: id},{password:hashPassword})
        return res.json({status:true, message: 'updated password'})
    } catch (error) {
       return res.json('invalid token')
        
    }

})

const verifyUser = async(req,res,next) => {
    const token = req.cookies.token;
    try{
    if(!token){
        return res.json({status: false, meassage: 'no token'})
    }
    const decoded = await jwt.verify(token, process.env.KEY);
    next()
} catch(error){
    return res.json(error)
}
}


router.get('/verify',verifyUser, (req,res)=>{
         return res.json({status:true,meassage:"authorized"})
})

router.get('/logout', (req,res)  => {
    res.clearCookie('token')
    return res.json({status:true})
})

export {router as UserRouter}