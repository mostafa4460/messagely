/** User class for message.ly */

const bcrypt = require("bcrypt");
const db = require("../db");
const {BCRYPT_WORK_FACTOR} = require("../config");
const ExpressError = require("../expressError");

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    try {
      if (!username || !password || !first_name || !last_name || !phone) {
        throw new ExpressError("Missing required data", 400);
      }
      const hashed = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      const result = await db.query(
        `INSERT INTO users VALUES ($1, $2, $3, $4, $5, LOCALTIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING username, password, first_name, last_name, phone`,
        [username, hashed, first_name, last_name, phone]
      );
      return result.rows[0];  
    } catch(e) {
      if (e.code === '23505') throw new ExpressError("Username already taken. Please try another one", 400);
      throw e;
    }
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    if (!username || !password) return false;
    const result = await db.query("SELECT password FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) return false;
    const hashedPW = result.rows[0].password;
    return await bcrypt.compare(password, hashedPW);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    await db.query(
      `UPDATE users SET last_login_at = CURRENT_TIMESTAMP
      WHERE username = $1`,
      [username]
    );
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone
      FROM users`
    );
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username = $1`,
      [username]
    );
    if (result.rows.length === 0) throw new ExpressError("Could not find user", 404);
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const messagesRes = await db.query(
      `SELECT m.id, 
              m.to_username AS username,
              u.first_name AS first_name,
              u.last_name AS last_name,
              u.phone AS phone,
              m.body,
              m.sent_at,
              m.read_at
      FROM messages AS m
      JOIN users AS u
      ON u.username = m.to_username
      WHERE m.from_username = $1`,
      [username]
    );
    if (messagesRes.rows.length === 0) throw new ExpressError("Could not find messages for this user", 404);
    const messages = messagesRes.rows.map(r => {
      return {
        id: r.id,
        to_user: {
          username: r.username,
          first_name: r.first_name,
          last_name: r.last_name,
          phone: r.phone
        },
        body: r.body,
        sent_at: r.sent_at,
        read_at: r.read_at
      }
    });
    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const messagesRes = await db.query(
      `SELECT m.id, 
              m.from_username AS username,
              u.first_name AS first_name,
              u.last_name AS last_name,
              u.phone AS phone,
              m.body,
              m.sent_at,
              m.read_at
      FROM messages AS m
      JOIN users AS u
      ON u.username = m.from_username
      WHERE m.to_username = $1`,
      [username]
    );
    if (messagesRes.rows.length === 0) throw new ExpressError("Could not find messages to this user", 404);
    const messages = messagesRes.rows.map(r => {
      return {
        id: r.id,
        from_user: {
          username: r.username,
          first_name: r.first_name,
          last_name: r.last_name,
          phone: r.phone
        },
        body: r.body,
        sent_at: r.sent_at,
        read_at: r.read_at
      }
    });
    return messages;
  }
}


module.exports = User;