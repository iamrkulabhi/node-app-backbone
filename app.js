console.log("Hello World from NodeJS.");

const express = require("express")
const bodyParser = require("body-parser")
const path = require("path")
const csrf = require("csurf")
const session = require("express-session")
const flash = require("connect-flash")
const SequelizeStore = require("connect-session-sequelize")(session.Store)

const authRoutes = require("./routes/auth")
const adminRoutes = require("./routes/admin")
const db = require("./models");

const PORT = process.env.PORT || 1234;
const sessionSecret = process.env.sessionSecret || 'mysecretkey';
const APP_NAME = process.env.APP_NAME || 'MY APP'
const sessionStore = new SequelizeStore({db: db.sequelize})
const app = express()

app.set('view engine', 'ejs')
app.set('views', 'views')

// app middleware goes here
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({secret: sessionSecret, store: sessionStore, resave: false, saveUninitialized: false}))
app.use(flash())
app.use(csrf())
app.use((req, res, next) => {
    res.locals.isUserLoggedIn = req.session.loggedIn
    res.locals.csfrToken = req.csrfToken()
    res.locals.appName = APP_NAME
    next()
})
app.use((req, res, next) => {
    if (!req.session.user) {
        return next()
    }
    db.user.findByPk(req.session.user.id)
    .then(user => {
        if(!user) {
            return next()
        }
        req.user = user
        next()
    })
    .catch(err => {
        next(new Error(err))
    })
})

// app routes goes here
app.use("/auth", authRoutes)
app.use("/admin", adminRoutes)

app.get("/500", (req, res, next) => {
    res.send("Something wrong.") // handle all exception
})
app.get((req, res, next) => { res.send("404 page") })
app.use((error, req, res, next) => {
    console.log(error) // printing all exception in log
    res.redirect("/500") // redirect to 500 page
})

db.sequelize
.sync()
//.sync({ force: true })
.then(() => {
    app.listen(PORT, () => {
        console.log(`App running on http://localhost:${PORT}`)
    })
})
.catch(err => {
    console.error(err)
})

