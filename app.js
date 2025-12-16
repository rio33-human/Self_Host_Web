const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const app = express();
const db = new sqlite3.Database(":memory:"); // in-memory DB for demo
const crypto = require("crypto");

function hashPassword(pwd) {
  return crypto.createHash("sha256").update(pwd).digest("hex");
}

// 🔓 Super weak "session" (global variable, shared by all users)
let currentUser = null;

// Parse form data
app.use(bodyParser.urlencoded({ extended: false }));

// Serve static files (React front page + CSS)
app.use(express.static(path.join(__dirname, "public")));

// --------- VERY NAIVE SECURITY HELPERS (still bypassable) ---------

// "WAF" that tries to detect SQLi patterns in login fields
function looksLikeSqlInjection(input) {
  if (!input) return false;
  const upper = input.toUpperCase();
  const patterns = [
    "' OR",
    "\" OR",
    " OR 1=1",
    "--",
    "/*",
    "*/",
    " UNION ",
    " SELECT ",
    " DROP ",
  ];
  return patterns.some((p) => upper.includes(p));
}

// Naive XSS sanitiser: only blocks literal "<script"
function sanitizeComment(content) {
  if (!content) return "";
  return content.replace(/<script/gi, "[blocked-script]");
}

// ---------- INITIAL DB SETUP (intentionally weak) ----------
db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      password TEXT,
      role TEXT,
      status TEXT
    )
  `);

  db.run(`
    CREATE TABLE topics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      description TEXT,
      author TEXT
    )
  `);

  db.run(`
    CREATE TABLE comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      topic_id INTEGER,
      author TEXT,
      content TEXT,
      status TEXT
    )
  `);

  // Plain-text passwords hashed with SHA-256 (still stored in DB, but not readable)
  // NOTE: SQL injection is still possible via username field.
  const adminHash = hashPassword("admin123");
  const aliceHash = hashPassword("password");
  const willieHash = hashPassword("mylove3000");
  const bobHash = hashPassword("password");

db.run(
  `INSERT INTO users (username, password, role, status)
   VALUES ('admin', '${adminHash}', 'admin', 'active')`
);
db.run(
  `INSERT INTO users (username, password, role, status)
   VALUES ('alice', '${aliceHash}', 'user', 'active')`
);
db.run(
  `INSERT INTO users (username, password, role, status)
   VALUES ('Willie', '${willieHash}', 'user', 'active')`
);
db.run(
  `INSERT INTO users (username, password, role, status)
   VALUES ('bob', '${bobHash}', 'user', 'banned')`
);

  // Create documents table for IDOR vulnerability - REAL FUNCTIONAL TABLE
  db.run(`
    CREATE TABLE documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      content TEXT,
      owner_id INTEGER,
      is_private INTEGER DEFAULT 1
    )
  `);

  // Seed some documents for IDOR testing - REAL DATA WITH SENSITIVE INFO
  db.run(`INSERT INTO documents (title, content, owner_id, is_private) VALUES ('Admin Secret Notes', 'Password: admin123\nAPI Key: sk_live_abc123xyz\nDatabase credentials: admin/password', 1, 1)`);
  db.run(`INSERT INTO documents (title, content, owner_id, is_private) VALUES ('Alice Personal Notes', 'My secret: I love chocolate\nBank account: 123456789\nSSN: 555-55-5555', 2, 1)`);
  db.run(`INSERT INTO documents (title, content, owner_id, is_private) VALUES ('Willie Private Diary', 'Dear diary, today I learned about SQL injection...', 3, 1)`);
  db.run(`INSERT INTO documents (title, content, owner_id, is_private) VALUES ('Public Announcement', 'This is a public document everyone can see', 1, 0)`);

  // Seed a topic
  db.run(
    `INSERT INTO topics (title, description, author)
     VALUES ('General Feedback', 'Share anything about the site here.', 'admin')`
  );
});

// ---------- HOME (Static HTML landing page) ----------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---------- LOGIN (still SQLi-vulnerable, with weak filter) ----------
app.get("/user/login", (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Login - Mini Feedback System</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">Login</h1>
      <p class="page-subtitle">Sign in to continue to your feedback dashboard.</p>

      <form method="POST" action="/user/login" class="form">
        <div class="form-group">
          <label>Username</label>
          <input name="username" class="input" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" class="input" />
        </div>
        <button type="submit" class="btn wide">Login</button>
      </form>
      <p class="hint">
        Demo accounts: <code>admin/admin123</code>, <code>alice/password</code>, <code>bob/password</code> (banned).
      </p>
    </div>
  </div>
</body>
</html>`);
});

app.post("/user/login", (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";
  const passwordHash = hashPassword(password); // ✅ add this

  // 🧼 Weak filter: tries to block obvious SQLi but is easy to bypass
  if (looksLikeSqlInjection(username) || looksLikeSqlInjection(password)) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Blocked Input</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/user/login" class="back-link">← Back to Login</a>
    <div class="card card-page">
      <h1 class="page-title">Suspicious input blocked</h1>
      <p>Your login request looks like it may contain SQL keywords. Please try again.</p>
      <p class="hint">Note: this filter is very simple and only checks for a few patterns.</p>
    </div>
  </div>
</body>
</html>`);
  }


// Still vulnerable: username is concatenated directly into SQL
const sql = `
  SELECT * FROM users
  WHERE username = '${username}' AND password = '${passwordHash}'
`;

  console.log("DEBUG SQL:", sql);

  db.get(sql, (err, row) => {
    if (err) {
      // ❌ VULNERABLE: Expose SQL error details for scanner detection
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    if (!row) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Login Failed</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">Login failed</h1>
      <p>The username or password you entered is incorrect.</p>
      <a href="/user/login" class="btn">Try Again</a>
    </div>
  </div>
</body>
</html>`);
    }

    if (row.status === "banned") {
      currentUser = null;
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Account Banned</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">Account banned</h1>
      <p>Your account has been banned by an administrator. You cannot post or create topics.</p>
    </div>
  </div>
</body>
</html>`);
    }

    // 🔓 "Session": global variable, no cookies, shared across everyone
    currentUser = {
      id: row.id,
      username: row.username,
      role: row.role,
      status: row.status,
    };

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Welcome - ${row.username}</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">Welcome, ${row.username}!</h1>
      <p>You are logged in as <strong>${row.role}</strong> (status: ${row.status}).</p>
      
      <div style="margin-top: 1.5rem;">
        <h2 class="section-title">Quick Links</h2>
        <ul class="comment-list">
          <li class="comment-item">
            <a href="/user/profile/${row.id}" class="back-link">View My Profile</a>
          </li>
          <li class="comment-item">
            <a href="/community" class="back-link">Community Topics</a>
          </li>
          <li class="comment-item">
            <a href="/documents/list" class="back-link">Browse Documents</a>
          </li>
          ${row.role === 'admin' ? '<li class="comment-item"><a href="/admin/panel" class="back-link">Admin Panel</a></li>' : ''}
        </ul>
      </div>
      
      <p class="hint" style="margin-top: 1rem;">You can now create topics, post comments, and manage documents in the community (unless banned).</p>
    </div>
  </div>
</body>
</html>`);
  });
});

app.get("/user/logout", (req, res) => {
  currentUser = null;
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Logged Out</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">You have been logged out.</h1>
      <p class="hint">This demo does not use real sessions, so this affects everyone using the app.</p>
    </div>
  </div>
</body>
</html>`);
});

// ---------- COMMUNITY: TOPIC LIST / CREATE TOPIC ----------
app.get("/community", (req, res) => {
  db.all("SELECT * FROM topics", (err, topics) => {
    if (err) return res.send("DB error");

    const topicsHtml = topics
      .map(
        (t) => `
      <li class="comment-item">
        <div><strong>${t.title}</strong> by <a href="/user/profile/${t.author}" class="back-link">${t.author}</a></div>
        <div class="hint">${t.description || ""}</div>
        <div style="margin-top:0.4rem;">
          <a href="/community/topic/${t.id}" class="btn">Open Topic</a>
        </div>
      </li>`
      )
      .join("");

    const loggedInText = currentUser
      ? `<span>Logged in as <strong>${currentUser.username}</strong> (${currentUser.role}, ${currentUser.status})</span> · <a href="/user/logout" class="back-link">Logout</a>`
      : `<span>You are browsing as guest.</span> · <a href="/user/login" class="back-link">Login</a>`;

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Community Topics - Mini Feedback System</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>

    <div class="card card-page">
      <h1 class="page-title">Community Topics</h1>
      <p class="page-subtitle">Open a topic and start chatting with others.</p>
      <p class="hint">${loggedInText}</p>

      <ul class="comment-list" style="margin-top:1rem;">
        ${topicsHtml || "<li class='comment-item empty'>No topics yet. Create the first one!</li>"}
      </ul>

      <h2 class="section-title">Create a new topic</h2>
      ${
        currentUser && currentUser.status !== "banned"
          ? `
      <form method="POST" action="/community/topic/create" class="form">
        <div class="form-group">
          <label>Topic Title</label>
          <input name="title" class="input" placeholder="What do you want to talk about?" />
        </div>
        <div class="form-group">
          <label>Description</label>
          <textarea name="description" class="textarea" placeholder="Optional short description"></textarea>
        </div>
        <button type="submit" class="btn wide">Create Topic</button>
      </form>
      `
          : `
      <p class="hint">
        You must be logged in and not banned to create a topic.
        <a href="/user/login">Login here</a>.
      </p>
      `
      }
    </div>
  </div>
</body>
</html>`);
  });
});

app.post("/community/topic/create", (req, res) => {
  if (!currentUser || currentUser.status === "banned") {
    return res.send("You must be logged in and not banned to create a topic.");
  }

  const title = req.body.title || "Untitled Topic";
  const description = req.body.description || "";

  db.run(
    "INSERT INTO topics (title, description, author) VALUES (?, ?, ?)",
    [title, description, currentUser.username],
    function (err) {
      if (err) return res.send("DB error");
      res.redirect("/community");
    }
  );
});

// ---------- TOPIC DETAIL + CHAT (stored XSS) ----------
app.get("/community/topic/:id", (req, res) => {
  const topicId = req.params.id;

  // ❌ topicId concatenated into SQL → SQL injection possible here
  const topicSql = `SELECT * FROM topics WHERE id = ${topicId}`;
  const commentsSql = `SELECT * FROM comments WHERE topic_id = ${topicId}`;

  db.get(topicSql, (err, topic) => {
    if (err) {
      // ❌ VULNERABLE: Expose SQL error for scanner detection
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while loading the topic.</p>
      <a href="/community" class="btn">Return to Topics</a>
    </div>
  </div>
</body>
</html>`);
    }
    if (!topic) return res.send("Topic not found or DB error");

    db.all(commentsSql, (err2, comments) => {
      if (err2) {
        // ❌ VULNERABLE: Expose SQL error for scanner detection
        return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while loading comments.</p>
      <a href="/community" class="btn">Return to Topics</a>
    </div>
  </div>
</body>
</html>`);
      }

      const commentsHtml = comments
        .map(
          (c) => `
        <li class="comment-item">
          <div><strong><a href="/user/profile/${c.author}" class="back-link">${c.author}</a></strong> says:</div>
          <div>${c.content}</div>
          <div class="hint">
            Status: ${c.status || "normal"}
            ${
              c.status === "warned"
                ? `<span class="tag tag-warned">Warned</span>`
                : ""
            }
            ${currentUser ? ` | <a href="/comment/edit/${c.id}" class="back-link">Edit</a> | <a href="/comment/delete/${c.id}" class="back-link">Delete</a>` : ''}
          </div>
        </li>`
        )
        .join("");

      const loggedInText = currentUser
        ? `<span>Logged in as <strong>${currentUser.username}</strong> (${currentUser.role}, ${currentUser.status})</span> · <a href="/user/logout" class="back-link">Logout</a>`
        : `<span>You are browsing as guest.</span> · <a href="/user/login" class="back-link">Login</a>`;

      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>${topic.title} - Chat</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/community" class="back-link">← Back to Topics</a>
    <div class="card card-page">
      <h1 class="page-title">${topic.title}</h1>
      <p class="page-subtitle">${topic.description || ""}</p>
      <p class="hint">${loggedInText}</p>

      <ul class="comment-list" style="margin-top:1rem;">
        ${
          commentsHtml ||
          "<li class='comment-item empty'>No messages yet. Start the conversation!</li>"
        }
      </ul>

      <h2 class="section-title">Post a message</h2>
      ${
        currentUser && currentUser.status !== "banned"
          ? `
      <form method="POST" action="/community/topic/${topic.id}/comment" class="form">
        <div class="form-group">
          <label>Message</label>
          <textarea name="content" class="textarea" placeholder="Write something..."></textarea>
        </div>
        <button type="submit" class="btn wide">Send</button>
      </form>
      `
          : `
      <p class="hint">You must be logged in and not banned to post a message.</p>
      `
      }
    </div>
  </div>
</body>
</html>`);
    });
  });
});

// Post comment (with naive XSS sanitisation)
app.post("/community/topic/:id/comment", (req, res) => {
  const topicId = req.params.id;

  if (!currentUser || currentUser.status === "banned") {
    return res.send("You must be logged in and not banned to post messages.");
  }

  // 🧼 This only removes literal "<script" – other XSS still possible.
  const content = sanitizeComment(req.body.content || "");

  db.run(
    "INSERT INTO comments (topic_id, author, content, status) VALUES (?, ?, ?, 'normal')",
    [topicId, currentUser.username, content],
    (err) => {
      if (err) return res.send("DB error");
      res.redirect(`/community/topic/${topicId}`);
    }
  );
});

// ---------- ADMIN PANEL (broken access control) ----------
// ---------- ADMIN PANEL (now uses "session", but other admin APIs are still weak) ----------
app.get("/admin/panel", (req, res) => {
  const sessionRole = currentUser ? currentUser.role : "guest";

  // ✅ Now you must actually be logged in as admin
  if (!currentUser || sessionRole !== "admin") {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Access Denied</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">Access denied</h1>
      <p>This section is restricted to system administrators.</p>
      <p class="hint">You must log in as <code>admin</code> to view this panel.</p>
    </div>
  </div>
</body>
</html>`);
  }

  db.all("SELECT * FROM users", (err, users) => {
    if (err) return res.send("DB error");

    db.all("SELECT * FROM comments", (err2, comments) => {
      if (err2) return res.send("DB error");

      const usersHtml = users
        .map(
          (u) => `
        <tr>
          <td>${u.id}</td>
          <td><a href="/user/profile/${u.id}" class="back-link">${u.username}</a></td>
          <td>${u.password}</td>
          <td>${u.role}</td>
          <td>${u.status}</td>
          <td>
            <a href="/admin/user/ban?id=${u.id}&role=admin" class="back-link">Ban</a> |
            <a href="/admin/user/unban?id=${u.id}&role=admin" class="back-link">Unban</a> |
            <a href="/admin/user/mod?id=${u.id}&role=admin" class="back-link">Make Moderator</a>
          </td>
        </tr>`
        )
        .join("");

      const commentsHtml = comments
        .map(
          (c) => `
        <tr>
          <td>${c.id}</td>
          <td><a href="/community/topic/${c.topic_id}" class="back-link">Topic ${c.topic_id}</a></td>
          <td><a href="/user/profile/${c.author}" class="back-link">${c.author}</a></td>
          <td>${c.content}</td>
          <td>${c.status || "normal"}</td>
          <td>
            <a href="/admin/comment/warn?id=${c.id}&role=admin" class="back-link">Warn</a> |
            <a href="/admin/comment/delete?id=${c.id}&role=admin" class="back-link">Delete</a> |
            <a href="/comment/edit/${c.id}" class="back-link">Edit</a>
          </td>
        </tr>`
        )
        .join("");

      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Admin Panel</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">Admin Panel</h1>
      <p class="page-subtitle">Manage users and moderate comments.</p>

      <h2 class="section-title">Users</h2>
      <table class="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Plain-text Password</th>
            <th>Role</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${usersHtml}
        </tbody>
      </table>

      <h2 class="section-title" style="margin-top:2rem;">Comments</h2>
      <table class="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Topic</th>
            <th>Author</th>
            <th>Content</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${commentsHtml || "<tr><td colspan='6'>No comments yet.</td></tr>"}
        </tbody>
      </table>

      <h2 class="section-title" style="margin-top:2rem;">Documents</h2>
      <p class="hint"><a href="/documents/list" class="back-link">View All Documents</a></p>
    </div>
  </div>
</body>
</html>`);
    });
  });
});


// ---------- ADMIN USER MANAGEMENT (still vulnerable) ----------
app.get("/admin/user/ban", (req, res) => {
  const roleParam = req.query.role;
  const id = req.query.id;

  if (roleParam !== "admin") return res.send("Access denied.");

  // ❌ SQL injection possible via id - VULNERABLE PATH #1
  const sql = `UPDATE users SET status = 'banned' WHERE id = ${id}`;
  db.run(sql, (err) => {
    if (err) {
      // ❌ VULNERABLE: Expose SQL error for scanner detection
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    res.redirect("/admin/panel?role=admin");
  });
});

app.get("/admin/user/unban", (req, res) => {
  const roleParam = req.query.role;
  const id = req.query.id;

  if (roleParam !== "admin") return res.send("Access denied.");

  // ❌ SQL injection possible via id - VULNERABLE PATH #2
  const sql = `UPDATE users SET status = 'active' WHERE id = ${id}`;
  db.run(sql, (err) => {
    if (err) {
      // ❌ VULNERABLE: Expose SQL error for scanner detection
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    res.redirect("/admin/panel?role=admin");
  });
});

app.get("/admin/user/mod", (req, res) => {
  const roleParam = req.query.role;
  const id = req.query.id;

  if (roleParam !== "admin") return res.send("Access denied.");

  // ❌ SQL injection possible via id - VULNERABLE PATH #3
  const sql = `UPDATE users SET role = 'moderator' WHERE id = ${id}`;
  db.run(sql, (err) => {
    if (err) {
      // ❌ VULNERABLE: Expose SQL error for scanner detection
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    res.redirect("/admin/panel?role=admin");
  });
});

// ---------- ADMIN COMMENT ACTIONS ----------
app.get("/admin/comment/delete", (req, res) => {
  const roleParam = req.query.role;
  const id = req.query.id;

  if (roleParam !== "admin") return res.send("Access denied.");

  const sql = `DELETE FROM comments WHERE id = ${id}`; // ❌ SQLi
  db.run(sql, (err) => {
    if (err) {
      // ❌ VULNERABLE: Expose SQL error for scanner detection
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    res.redirect("/admin/panel?role=admin");
  });
});

app.get("/admin/comment/warn", (req, res) => {
  const roleParam = req.query.role;
  const id = req.query.id;

  if (roleParam !== "admin") return res.send("Access denied.");

  const sql = `UPDATE comments SET status = 'warned' WHERE id = ${id}`; // ❌ SQLi
  db.run(sql, (err) => {
    if (err) {
      // ❌ VULNERABLE: Expose SQL error for scanner detection
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    res.redirect("/admin/panel?role=admin");
  });
});

// ---------- IDOR VULNERABILITIES (Insecure Direct Object Reference) ----------

// ❌ IDOR VULNERABILITY #1: User profile endpoint - no authorization check
// Users can access any user's profile by changing the user_id parameter
app.get("/user/profile/:user_id", (req, res) => {
  const userId = req.params.user_id;
  
  // ❌ VULNERABLE: No check if currentUser.id matches userId - anyone can view any profile
  const sql = `SELECT id, username, role, status FROM users WHERE id = ${userId}`;
  
  db.get(sql, (err, user) => {
    if (err) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    
    if (!user) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>User Not Found</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">User Not Found</h1>
      <p>User ID ${userId} does not exist.</p>
    </div>
  </div>
</body>
</html>`);
    }
    
    // Get user's documents and activity
    db.all(`SELECT * FROM documents WHERE owner_id = ${user.id}`, (err2, userDocs) => {
      // Get user ID for topics query - need to find user ID from username
      db.all(`SELECT * FROM topics WHERE author = '${user.username.replace(/'/g, "''")}'`, (err3, userTopics) => {
        db.all(`SELECT * FROM comments WHERE author = '${user.username.replace(/'/g, "''")}'`, (err4, userComments) => {
          
          const docsHtml = userDocs && userDocs.length > 0
            ? userDocs.map(d => `<li class="comment-item"><a href="/documents/${d.id}" class="back-link">${d.title}</a> ${d.is_private ? '(Private)' : '(Public)'}</li>`).join('')
            : '<li class="comment-item empty">No documents</li>';
          
          const topicsHtml = userTopics && userTopics.length > 0
            ? userTopics.map(t => `<li class="comment-item"><a href="/community/topic/${t.id}" class="back-link">${t.title}</a></li>`).join('')
            : '<li class="comment-item empty">No topics created</li>';
          
          const commentsHtml = userComments && userComments.length > 0
            ? userComments.map(c => `<li class="comment-item"><a href="/community/topic/${c.topic_id}" class="back-link">Comment #${c.id}</a> in Topic ${c.topic_id}</li>`).join('')
            : '<li class="comment-item empty">No comments posted</li>';

          res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>User Profile - ${user.username}</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">User Profile: ${user.username}</h1>
      <p><strong>User ID:</strong> ${user.id}</p>
      <p><strong>Username:</strong> ${user.username}</p>
      <p><strong>Role:</strong> ${user.role}</p>
      <p><strong>Status:</strong> ${user.status}</p>
      
      <h2 class="section-title" style="margin-top:1.5rem;">Documents (${userDocs ? userDocs.length : 0})</h2>
      <ul class="comment-list">
        ${docsHtml}
      </ul>
      
      <h2 class="section-title" style="margin-top:1.5rem;">Topics Created (${userTopics ? userTopics.length : 0})</h2>
      <ul class="comment-list">
        ${topicsHtml}
      </ul>
      
      <h2 class="section-title" style="margin-top:1.5rem;">Comments Posted (${userComments ? userComments.length : 0})</h2>
      <ul class="comment-list">
        ${commentsHtml}
      </ul>
      
    </div>
  </div>
</body>
</html>`);
        });
      });
    });
  });
});

// ❌ IDOR VULNERABILITY #2: Edit/Delete comments - no ownership check
// Users can edit or delete any comment by changing the comment_id
app.get("/comment/edit/:comment_id", (req, res) => {
  const commentId = req.params.comment_id;
  
  if (!currentUser) {
    return res.send("You must be logged in to edit comments.");
  }
  
  // ❌ VULNERABLE: No check if comment belongs to currentUser - anyone can edit any comment
  const sql = `SELECT * FROM comments WHERE id = ${commentId}`;
  
  db.get(sql, (err, comment) => {
    if (err) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    
    if (!comment) {
      return res.send("Comment not found.");
    }
    
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Edit Comment</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/community/topic/${comment.topic_id}" class="back-link">← Back to Topic</a>
    <div class="card card-page">
      <h1 class="page-title">Edit Comment</h1>
      <p class="hint">Original Author: ${comment.author}</p>
      <form method="POST" action="/comment/update/${commentId}" class="form">
        <div class="form-group">
          <label>Comment Content</label>
          <textarea name="content" class="textarea">${comment.content}</textarea>
        </div>
        <button type="submit" class="btn wide">Update Comment</button>
      </form>
    </div>
  </div>
</body>
</html>`);
  });
});

app.post("/comment/update/:comment_id", (req, res) => {
  const commentId = req.params.comment_id;
  const newContent = sanitizeComment(req.body.content || "");
  
  if (!currentUser) {
    return res.send("You must be logged in to update comments.");
  }
  
  // ❌ VULNERABLE: No ownership check - anyone can update any comment
  // Also vulnerable to SQL injection via commentId (numeric injection)
  const sql = `UPDATE comments SET content = '${newContent.replace(/'/g, "''")}' WHERE id = ${commentId}`;
  
  db.run(sql, (err) => {
    if (err) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    
    // Get topic_id to redirect
    db.get(`SELECT topic_id FROM comments WHERE id = ${commentId}`, (err2, result) => {
      if (err2 || !result) return res.send("Error redirecting");
      res.redirect(`/community/topic/${result.topic_id}`);
    });
  });
});

// ❌ IDOR VULNERABILITY: Delete comment - no ownership check - REAL FUNCTIONAL ENDPOINT
app.get("/comment/delete/:comment_id", (req, res) => {
  const commentId = req.params.comment_id;
  
  if (!currentUser) {
    return res.send("You must be logged in to delete comments.");
  }
  
  // ❌ VULNERABLE: No ownership check - anyone can delete any comment
  // First get the comment to find topic_id for redirect
  const sql = `SELECT topic_id, author FROM comments WHERE id = ${commentId}`;
  
  db.get(sql, (err, comment) => {
    if (err) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    
    if (!comment) {
      return res.send("Comment not found.");
    }
    
    // Delete the comment - NO AUTHORIZATION CHECK
    const deleteSql = `DELETE FROM comments WHERE id = ${commentId}`;
    db.run(deleteSql, (err2) => {
      if (err2) {
        return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while deleting the comment.</p>
      <a href="/community" class="btn">Return to Community</a>
    </div>
  </div>
</body>
</html>`);
      }
      
      // Success - redirect back to topic
      res.redirect(`/community/topic/${comment.topic_id}`);
    });
  });
});

// Documents list page - shows all documents
app.get("/documents/list", (req, res) => {
  const sql = `SELECT d.*, u.username as owner_name FROM documents d LEFT JOIN users u ON d.owner_id = u.id ORDER BY d.id`;
  
  db.all(sql, (err, docs) => {
    if (err) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/documents/list" class="btn">Return to Documents</a>
    </div>
  </div>
</body>
</html>`);
    }
    
    const docsHtml = docs && docs.length > 0
      ? docs.map(d => `
        <li class="comment-item">
          <div><strong><a href="/documents/${d.id}" class="back-link">${d.title}</a></strong></div>
          <div class="hint">Owner: <a href="/user/profile/${d.owner_id}" class="back-link">${d.owner_name || 'Unknown'}</a> | ${d.is_private ? 'Private' : 'Public'}</div>
        </li>`).join('')
      : '<li class="comment-item empty">No documents found</li>';
    
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Documents List</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">All Documents</h1>
      <p class="page-subtitle">Browse all available documents in the system.</p>
      <ul class="comment-list" style="margin-top:1rem;">
        ${docsHtml}
      </ul>
      ${currentUser ? `<p class="hint" style="margin-top:1rem;"><a href="/documents/create" class="back-link">Create New Document</a></p>` : ''}
    </div>
  </div>
</body>
</html>`);
  });
});

// Create document page
app.get("/documents/create", (req, res) => {
  if (!currentUser) {
    return res.send("You must be logged in to create documents.");
  }
  
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Create Document</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/documents/list" class="back-link">← Back to Documents</a>
    <div class="card card-page">
      <h1 class="page-title">Create New Document</h1>
      <form method="POST" action="/documents/create" class="form">
        <div class="form-group">
          <label>Title</label>
          <input name="title" class="input" placeholder="Document title" required />
        </div>
        <div class="form-group">
          <label>Content</label>
          <textarea name="content" class="textarea" placeholder="Document content" required></textarea>
        </div>
        <div class="form-group">
          <label>
            <input type="checkbox" name="is_private" value="1" checked />
            Private Document
          </label>
        </div>
        <button type="submit" class="btn wide">Create Document</button>
      </form>
    </div>
  </div>
</body>
</html>`);
});

app.post("/documents/create", (req, res) => {
  if (!currentUser) {
    return res.send("You must be logged in to create documents.");
  }
  
  const title = req.body.title || "Untitled";
  const content = req.body.content || "";
  const isPrivate = req.body.is_private ? 1 : 0;
  
  db.run(
    `INSERT INTO documents (title, content, owner_id, is_private) VALUES (?, ?, ?, ?)`,
    [title, content, currentUser.id, isPrivate],
    function(err) {
      if (err) return res.send("DB error: " + err.message);
      res.redirect(`/documents/${this.lastID}`);
    }
  );
});

// ❌ IDOR VULNERABILITY #3: View private messages/documents by ID - REAL FUNCTIONAL ENDPOINT
// Users can access any document by guessing/changing the document_id
app.get("/documents/:document_id", (req, res) => {
  const documentId = req.params.document_id;
  
  // ❌ VULNERABLE: No authorization check - any user can access any document
  // No check if currentUser.id matches owner_id - REAL IDOR VULNERABILITY
  const sql = `SELECT id, title, content, owner_id, is_private FROM documents WHERE id = ${documentId}`;
  
  db.get(sql, (err, doc) => {
    if (err) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Database Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Database Error</h1>
      <p>An error occurred while processing your request.</p>
      <a href="/user/login" class="btn">Return to Login</a>
    </div>
  </div>
</body>
</html>`);
    }
    
    if (!doc) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Document Not Found</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Document Not Found</h1>
      <p>Document ID ${documentId} does not exist.</p>
    </div>
  </div>
</body>
</html>`);
    }
    
    // Get owner username from users table
    db.get(`SELECT username FROM users WHERE id = ${doc.owner_id}`, (err2, owner) => {
      const ownerName = owner ? owner.username : `User ${doc.owner_id}`;
      const currentUserName = currentUser ? currentUser.username : "Not logged in";
      const currentUserId = currentUser ? currentUser.id : "N/A";
      
      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Document - ${doc.title}</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/documents/list" class="back-link">← Back to Documents</a>
    <div class="card card-page">
      <h1 class="page-title">${doc.title}</h1>
      <p><strong>Document ID:</strong> ${doc.id}</p>
      <p><strong>Owner:</strong> <a href="/user/profile/${doc.owner_id}" class="back-link">${ownerName}</a> (User ID: ${doc.owner_id})</p>
      <p><strong>Private Document:</strong> ${doc.is_private ? 'Yes' : 'No'}</p>
      <div style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.2); border-radius: 0.5rem;">
        <strong>Document Content:</strong>
        <pre style="white-space: pre-wrap; margin-top: 0.5rem;">${doc.content}</pre>
      </div>
    </div>
  </div>
</body>
</html>`);
    });
  });
});

// ---------- PATH TRAVERSAL VULNERABILITIES ----------

// ❌ PATH TRAVERSAL VULNERABILITY #1: File reading endpoint
// User input is directly used to read files without sanitization
app.get("/api/file", (req, res) => {
  const fileName = req.query.file || "";
  
  if (!fileName) {
    return res.send("Error: file parameter required. Usage: /api/file?file=filename");
  }
  
  // ❌ VULNERABLE: Path traversal - no sanitization of fileName
  // Attackers can use ../../../etc/passwd or similar to read arbitrary files
  // path.join() normalizes paths, but path.resolve() allows traversal - MAKING IT ACTUALLY VULNERABLE
  // This is a REAL path traversal vulnerability that actually works
  const filePath = path.resolve(__dirname, "public", fileName);
  
  // Try to read the file - THIS ACTUALLY READS FILES FROM THE FILESYSTEM
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>File Read Error</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">File Read Error</h1>
      <p>Error reading file: ${err.message}</p>
    </div>
  </div>
</body>
</html>`);
    }
    
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>File Contents</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">File Contents</h1>
      <p><strong>File:</strong> ${fileName}</p>
      <pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; overflow-x: auto;">${data}</pre>
    </div>
  </div>
</body>
</html>`);
  });
});

// ❌ PATH TRAVERSAL VULNERABILITY #2: Template/include file reading
// Another common path traversal pattern
app.get("/include", (req, res) => {
  const includeFile = req.query.page || "index.html";
  
  // ❌ VULNERABLE: Direct use of user input in file path - REAL PATH TRAVERSAL
  // path.resolve() allows directory traversal sequences to work
  // This is a REAL vulnerability that actually reads files outside the public directory
  const includePath = path.resolve(__dirname, "public", includeFile);
  
  fs.readFile(includePath, "utf8", (err, content) => {
    if (err) {
      return res.send(`Error including file: ${err.message}`);
    }
    
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Included File</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <div class="card card-page">
      <h1 class="page-title">Included File</h1>
      <p><strong>File:</strong> ${includeFile}</p>
      <pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; overflow-x: auto;">${content}</pre>
    </div>
  </div>
</body>
</html>`);
  });
});

// ---------- START SERVER ----------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable app running on http://localhost:${PORT}`);
});
