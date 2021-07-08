const express = require('express')
const router = express.Router()
const mongoose = require('mongoose')
const User = mongoose.model("User")
const crypto = require('crypto')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const {JWT_SECRET} = require('../config/keys')
const requireLogin = require('../middleware/requireLogin')
const nodemailer = require('nodemailer')
const {PASS,EMAIL} = require('../config/keys')

const transporter = nodemailer.createTransport({
   host:'smtp.gmail.com',
   port:587,
   secure:false,
   requireTLS: true,
   auth:{
       user:EMAIL,
       pass:PASS
    }

});


router.post('/signup',(req,res)=>{
  const {name,email,password,pic} = req.body 
  if(!email || !password || !name){
     return res.status(422).json({error:"please add all the fields"})
  }
  User.findOne({email:email})
  .then((savedUser)=>{
      if(savedUser){
        return res.status(422).json({error:"user already exists with that email"})
      }
      bcrypt.hash(password,12)
      .then(hashedpassword=>{
            const user = new User({
                email,
                password:hashedpassword,
                name,
                pic
            })
    
            user.save()
            .then(user=>{
                  transporter.sendMail({
                      to:user.email,
                      from:EMAIL,
                       subject:"signup success",
                       html:`
                       <p>Hi,${user.name}</p>
                       <div style="background-color:black;width:100%;text-align:center;color:white;">
                      <br>
                       <p>Welcome to Social point<p>
                       <p>you have successfully signup</p>
                       <br>
                       
                       </div>
                       <p>From<br>Social point</p>
                       `
                   })
                res.json({message:"saved successfully"})
            })
            .catch(err=>{
                console.log(err)
            })
      })
     
  })
  .catch(err=>{
    console.log(err)
  })
})


router.post('/signin',(req,res)=>{
    const {email,password} = req.body
    if(!email || !password){
       return res.status(422).json({error:"please add email or password"})
    }
    User.findOne({email:email})
    .then(savedUser=>{
        if(!savedUser){
           return res.status(422).json({error:"Invalid Email or password"})
        }
        bcrypt.compare(password,savedUser.password)
        .then(doMatch=>{
            if(doMatch){
                // res.json({message:"successfully signed in"})
               const token = jwt.sign({_id:savedUser._id},JWT_SECRET)
               const {_id,name,email,followers,following,pic} = savedUser
               res.json({token,user:{_id,name,email,followers,following,pic}})
            }
            else{
                return res.status(422).json({error:"Invalid Email or password"})
            }
        })
        .catch(err=>{
            console.log(err)
        })
    })
})


router.post('/reset-password',(req,res)=>{
     crypto.randomBytes(32,(err,buffer)=>{
         if(err){
             console.log(err)
         }
         const token = buffer.toString("hex")
         User.findOne({email:req.body.email})
         .then(user=>{
             if(!user){
                 return res.status(422).json({error:"User dont exists with that email"})
             }
             user.resetToken = token
             user.expireToken = Date.now() + 3600000
             user.save().then((result)=>{
                 transporter.sendMail({
                     to:user.email,
                     from:EMAIL,
                     subject:"password reset",
                     html:`
                     <p>Hi,${user.name}</p>
                     <div style="background-color:black;width:100%;text-align:center;color:white;">
                    <br>
                     <p>You requested for password reset</p>
                     <p>click on the button  <a href="${EMAIL}/reset/${token}"><button style="background-color:red;color:white;">Reset Password</button></a>  to reset password</p>
                     <br>
                    
                     </div>
                     <p>From<br>Social point</p>
                     `
                 })
                 res.json({message:"check your email"})
             })

         })
     })
})

//<h5>click in this <a href="http://localhost:3000/reset/${token}">link</a> to reset password</h5>
router.post('/new-password',(req,res)=>{
    const newPassword = req.body.password
    const sentToken = req.body.token
    User.findOne({resetToken:sentToken,expireToken:{$gt:Date.now()}})
    .then(user=>{
        if(!user){
            return res.status(422).json({error:"Try again session expired"})
        }
        bcrypt.hash(newPassword,12).then(hashedpassword=>{
           user.password = hashedpassword
           user.resetToken = undefined
           user.expireToken = undefined
           user.save().then((saveduser)=>{
               res.json({message:"password updated success"})
           })
        })
    }).catch(err=>{
        console.log(err)
    })
})


module.exports = router