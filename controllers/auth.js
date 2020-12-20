const crypto = require("crypto")
const bcrypt = require("bcryptjs")
const { validationResult } = require("express-validator")
const Sequelize = require("sequelize")

const db = require("../models")
const mailer = require("../utils/mail")
const Op = Sequelize.Op
const salt = bcrypt.genSaltSync(12)

exports.getLogin = (req, res, next) => {
    let errorMsg = req.flash('error')
    if(errorMsg.length > 0) {
        errorMsg = errorMsg[0]
    } else {
        errorMsg = null
    }
    
    res.render('auth/login', {
        title: 'Sign In',
        actionUrl: '/auth/login',
        errorMsg: errorMsg,
        oldValues: { name: '', email: ''},
        validationErrors: []
    })
}

exports.postLogin = (req, res, next) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        console.log(errors.array())
        return res.status(422).render('auth/login', {
            title: 'Sign Up',
            actionUrl: '/auth/login',
            errorMsg: errors.array()[0].msg,
            oldValues: { email: req.body.email},
            validationErrors: errors.array()
        })
    }

    db.user.findOne({where: {email: req.body.email}})
    .then(user => {
        req.session.loggedIn = true
        req.session.user = user
        req.session.save(err => {
            res.redirect("/admin")
        })
    })
    .catch(err => {
        const error = new Error(err)
        error.httpStatusCode = 500
        return next(error)
    })
}

exports.getRegister = (req, res, next) => {
    let errorMsg = req.flash('error')
    if(errorMsg.length > 0) {
        errorMsg = errorMsg[0]
    } else {
        errorMsg = null
    }

    res.render('auth/register', {
        title: 'Sign Up',
        actionUrl: '/auth/register',
        errorMsg: errorMsg,
        oldValues: { name: '', email: ''},
        validationErrors: []
    })
}

exports.postRegister = (req, res, next) => {
    //console.log(req.body)
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        console.log(errors.array())
        return res.status(422).render('auth/register', {
            title: 'Sign Up',
            actionUrl: '/auth/register',
            errorMsg: errors.array()[0].msg,
            oldValues: { name: req.body.name, email: req.body.email},
            validationErrors: errors.array()
        })
    }
    const hash = bcrypt.hashSync(req.body.password, salt)
    const newUser = db.user.build({
        name: req.body.name,
        email: req.body.email,
        password: hash
    })
    newUser.save()
    .then(result => {
        res.redirect('/auth/login')
    })
    .catch(err => {
        const error = new Error(err)
        error.httpStatusCode = 500
        return next(error)
    })
}

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        if (err) {
            const error = new Error(err)
            error.httpStatusCode = 500;
            return next(error)
        }
        res.redirect("/auth/login")
    })
}

exports.getForgetPassword = (req, res, next) => {
    let errorMsg = req.flash('error')
    if(errorMsg.length > 0) {
        errorMsg = errorMsg[0]
    } else {
        errorMsg = null
    }

    res.render('auth/forget-password', {
        title: 'Forget Password',
        actionUrl: '/auth/forget-password',
        errorMsg: errorMsg,
        oldValues: { email: ''},
        validationErrors: []
    })
}

exports.postForgetPassword = (req, res, next) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        console.log(errors.array())
        return res.status(422).render('auth/forget-password', {
            title: 'Forget Password',
            actionUrl: '/auth/forget-password',
            errorMsg: errors.array()[0].msg,
            oldValues: { email: req.body.email},
            validationErrors: errors.array()
        })
    }
    crypto.randomBytes(32, (err, buffer) => {
        if (err) {
            req.flash('error', 'Something wrong, please try again')
            return res.redirect("/auth/forget-password")
        }
        const token = buffer.toString('hex')
        db.user.findOne({where: {email: req.body.email}})
        .then(user => {
            user.token = token
            user.tokenExpire = Date.now()+3600000
            return user.save()
        })
        .then(result => {
            const emailOption = {
                to: [req.body.email],
                from: 'rahul.kulabhi@codeclouds.in',
                subject: 'Forget password request',
                html: `<h3>Want to Reset password?</h3><p>To reset password <a href="http://localhost:1234/update-password/${token}">click here</a> to proceed.</p>`
            }
            mailer.sendMail(emailOption, (err, data) => {
                if (err) {
                    console.log(err)
                    req.flash('error', 'Something wrong while sending verification email')
                    return res.redirect("/auth/forget-password")
                }
                console.log(data)
                res.redirect("/auth/login")
            })
        })
        .catch(err => {
            const error = new Error(err)
            error.httpStatusCode = 500
            return next(error)
        })
    })
}

exports.getUpdatePassword = (req, res, next) => {
    const token = req.params.token
    //console.log(token)
    
    db.user.findOne({
        where: {
            token: token,
            tokenExpire: {[Op.gt]: Date.now()}
        }
    })
    .then(user => {
        if(!user){
            req.flash('error', `${token} is not valid`)
            return res.redirect("/auth/forget-password/")
        }
        let errorMsg = req.flash('error')
        if(errorMsg.length > 0) {
            errorMsg = errorMsg[0]
        } else {
            errorMsg = null
        }
    
        res.render('auth/update-password', {
            title: 'Update Password',
            actionUrl: '/auth/new-password',
            errorMsg: errorMsg,
            userId: user.id,
            token: token,
            oldValues: {},
            validationErrors: []
        })

    })
    
}

exports.postNewPassword = (req, res, next) => {
    const userId = req.body.userId
    const token = req.body.token
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        console.log(errors.array())
        return res.status(422).render('auth/update-password', {
            title: 'Update Password',
            actionUrl: '/auth/new-password',
            errorMsg: errors.array()[0].msg,
            userId: userId,
            token: token,
            oldValues: {},
            validationErrors: []
        })
    }
    db.user.findOne({
        where: {
            token: token,
            tokenExpire: {[Op.gt]: Date.now()},
            id: userId
        }
    })
    .then(user => {
        if (!user) {
            req.flash('error', 'Something wrong, please try again')
            return res.redirect("/auth/update-password/" + token)
        }
        const hash = bcrypt.hashSync(req.body.password, salt)
        user.password = hash
        user.token = ''
        return user.save()
    })
    .then(result => {
        res.redirect("/auth/login")
    })
    .catch(err => {
        const error = new Error(err)
        error.httpStatusCode = 500
        return next(error)
    })
}



