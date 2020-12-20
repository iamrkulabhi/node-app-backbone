const express = require("express")
const router = express.Router()
const { body } = require("express-validator")
const bcrypt = require("bcryptjs")

const db = require("../models")
const authCtrl = require("../controllers/auth")
const guestMiddleware = require("../middlewares/is-guest")
const authMiddleware = require("../middlewares/is-auth")

router.get("/login", guestMiddleware, authCtrl.getLogin);

router.post("/login", guestMiddleware,
[
    body("email")
    .isEmail()
    .withMessage("Please enter valid email")
    .custom((value, {req}) => {
        return db.user.findOne({where: {email: value}})
        .then(user => {
            if(!user) {
                return Promise.reject("User is not found with this email")
            }
        }) 
    }),
    body("password")
    .isLength({min: 5})
    .withMessage("Password should be length og 5 charecters")
    .custom((value, {req}) => {
        return db.user.findOne({where: {email: req.body.email}})
        .then(user => {
            if(user && !bcrypt.compareSync(value, user.password)) {
                return Promise.reject("Invalid user")
            }
        })
    })
],
authCtrl.postLogin);

router.get("/register", guestMiddleware, authCtrl.getRegister);

router.post("/register", guestMiddleware,
[
    body("name").isLength({min: 3}).withMessage("Please enter valid name"),
    body("email").isEmail().withMessage("Please enter valid email")
    .custom((value, {req}) => {
        return db.user.findOne({where: {email: value}})
        .then(user => {
            if (user) {
                return Promise.reject('User already exist with is email')
            }
        })
    }),
    body(
        "password",
        "Password should be of length 5 charecter"
        ).isLength({min: 5}),
    body(
        "confirm_password",
        "Password should be of length 5 charecter"
        )
        .isLength({min: 5})
        .custom((value, {req}) => {
            if(value !== req.body.password){
                throw new Error("Confirm Password have to be matched")
            }
            return true;
        })
],
authCtrl.postRegister);

router.get("/forget-password", guestMiddleware, authCtrl.getForgetPassword);

router.post("/forget-password", guestMiddleware,
[
    body("email")
    .isEmail()
    .withMessage("Please enter valid email")
    .custom((value, {req}) => {
        return db.user.findOne({where: {email: value}})
        .then(user => {
            if(!user) {
                return Promise.reject("User is not found with this email")
            }
        }) 
    })
],
authCtrl.postForgetPassword);

router.get("/update-password/:token", guestMiddleware, authCtrl.getUpdatePassword);

router.post("/new-password", guestMiddleware, 
[
    body(
        "password",
        "Password should be of length 5 charecter"
        ).isLength({min: 5}),
    body(
        "confirm_password",
        "Password should be of length 5 charecter"
        )
        .isLength({min: 5})
        .custom((value, {req}) => {
            if(value !== req.body.password){
                throw new Error("Confirm Password have to be matched")
            }
            return true;
        })
],
authCtrl.postNewPassword);

router.post("/logout", authMiddleware, authCtrl.postLogout)

module.exports = router;

