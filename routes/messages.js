/** messages routes */

const express = require("express");
const router = new express.Router();
const Message = require("../models/message");
const {ensureLoggedIn} = require("../middleware/auth");
const ExpressError = require("../expressError");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get('/:id', ensureLoggedIn, async (req, res, next) => {
    try {
        const message = await Message.get(req.params.id);
        const isSender = req.user.username === message.from_user.username;
        const isReceiver = req.user.username === message.to_user.username;
        if (isSender || isReceiver) {
            return res.json({message});
        }
        throw new ExpressError("Unauthorized", 401);
    } catch(e) {
        return next(e);
    }
})

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post('/', ensureLoggedIn, async (req, res, next) => {
    try {
        const {to_username, body} = req.body;
        const from_username = req.user.username;
        const message = await Message.create({from_username, to_username, body});
        return res.json({message});
    } catch(e) {
        return next(e);
    }
})


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post('/:id/read', ensureLoggedIn, async (req, res, next) => {
    try {
        const sentMsg = await Message.get(req.params.id);
        const isRecipient = req.user.username === sentMsg.to_user.username;
        if (isRecipient) {
            const message = await Message.markRead(req.params.id);
            return res.json({message});
        }
        throw new ExpressError("Unauthorized", 401);
    } catch(e) {
        return next(e);
    }
})

module.exports = router;