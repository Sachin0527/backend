import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
 
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        index: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        index: true,
        trim: true,
    },
    avatar: {
        type: String,
        required: true,
    },
    coverImage: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: [true, "Password is required"],
    },
    fullName: {
        type: String,
        required: true,
    },
    watchHistory: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Video",
            }
        ],
}, {
        timestamps:true
    });

    userSchema.pre("save", async function(next){
        if(!this.isModified("password")){
            return next();
        }
        this.password = await bcrypt.hash(this.password, 10);
        next();
    })

    userSchema.methods.comparePassword = async function(password){
        return await bcrypt.compare(password, this.password);
    }
    userSchema.methods.generateToken = function(){
        return jwt.sign({
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
             process.env.ACCESS_TOKEN_SECRET, 
             {expiresIn: process.env.ACCESS_TOKEN_EXPIRY});
    }

    userSchema.methods.generateRefreshToken = function(){
        return jwt.sign({
            _id: this._id,
        },
             process.env.REFRESH_TOKEN_SECRET, 
             {expiresIn: process.env.REFRESH_TOKEN_EXPIRY});
    }

export const User = mongoose.model("User", userSchema);