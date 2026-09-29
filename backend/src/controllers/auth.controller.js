const userModel = require('../models/user.models')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

async function registerUser(req,res){

    const {fullName, email, phone, password} = req.body;

    const isUserExist = await userModel.findOne({email, phone});
    
    if(isUserExist){
        return res.status(400).json({
            message:'User already exist'
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await userModel.create({
        fullName,
        email,
        phone,
        password:hashedPassword
    })

    const token = jwt.sign({
        id:user._id
    },process.env.JWT_SECRET)

    res.cookie("token", token) 

    res.status(201).json({
        message:'User registered successfully',
        user:{
            id:user._id,
            fullName:user.fullName,
            email:user.email,
            phone:user.phone
        }
    })

}

async function loginUser(req,res){
    
    const {email,password} = req.body;

    const isUserExist = await userModel.findOne({email})

    if(!isUserExist){
        return res.status(400).json({
            message:'Invalid email or password'
        })
    }

    const isPasswordValid = await bcrypt.compare(password, isUserExist.password)

    if(!isPasswordValid){
        return res.status(400).json({
            message:'Invalid email or password'
        })
    }

    const token = jwt.sign({
        id:isUserExist._id
    },process.env.JWT_SECRET)

    res.cookie("token", token) 

    res.status(200).json({
        message:'User logged in successfully',
        user:{
            id:isUserExist._id,
            fullName:isUserExist.fullName,
            email:isUserExist.email,
            phone:isUserExist.phone
        }
    })

}

function logoutUser(req,res){
    res.clearCookie("token");
    
    res.status(200).json({
        message:'User logged out successfully'
    })

}

module.exports = {
    registerUser,
    loginUser,
    logoutUser
}   