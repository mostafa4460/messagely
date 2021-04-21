/** Authenticate user routes */

const express = require("express");
const ExpressError = require("../expressError");
const router = new express.Router();
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const {SECRET_KEY} = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async (req, res, next) => {
    try {
        const {username, password} = req.body;
        if (await User.authenticate(username, password)) {
            await User.updateLoginTimestamp(username);
            const token = jwt.sign({username}, SECRET_KEY);
            return res.json({token});
        }
        throw new ExpressError("Invalid username / password", 400);
    } catch(e) {
        return next(e);
    }
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async (req, res, next) => {
    try {
        const user = await User.register(req.body);
        const token = jwt.sign({username: user.username}, SECRET_KEY);
        return res.json({token});
    } catch(e) {
        return next(e);
    }
})

module.exports = router;