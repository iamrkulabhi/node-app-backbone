const express = require("express")
const router =  express.Router()

const adminCtrl = require("../controllers/admin")
const authMiddleware = require("../middlewares/is-auth")

router.get("/", authMiddleware, adminCtrl.getBlank)

module.exports = router


