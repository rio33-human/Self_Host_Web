const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

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


  // Seed a topic
  db.run(
    `INSERT INTO topics (title, description, author)
     VALUES ('General Feedback', 'Share anything about the site here.', 'admin')`
  );
});

// ---------- HOME (React landing page) ----------
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
      return res.send("DB error");
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
  <title>Welcome</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="page">
  <div class="page-container">
    <a href="/" class="back-link">← Back to Home</a>
    <div class="card card-page">
      <h1 class="page-title">Welcome, ${row.username}</h1>
      <p>You are logged in as <strong>${row.role}</strong> (status: ${row.status}).</p>
      <p class="hint">You can now create topics and post comments in the community (unless banned).</p>
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
        <div><strong>${t.title}</strong> by ${t.author}</div>
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
    if (err || !topic) return res.send("Topic not found or DB error");

    db.all(commentsSql, (err2, comments) => {
      if (err2) return res.send("DB error");

      const commentsHtml = comments
        .map(
          (c) => `
        <li class="comment-item">
          <div><strong>${c.author}</strong> says:</div>
          <div>${c.content}</div>
          <div class="hint">
            Status: ${c.status || "normal"}
            ${
              c.status === "warned"
                ? `<span class="tag tag-warned">Warned</span>`
                : ""
            }
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
          <td>${u.username}</td>
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
          <td>${c.topic_id}</td>
          <td>${c.author}</td>
          <td>${c.content}</td>
          <td>${c.status || "normal"}</td>
          <td>
            <a href="/admin/comment/warn?id=${c.id}&role=admin" class="back-link">Warn</a> |
            <a href="/admin/comment/delete?id=${c.id}&role=admin" class="back-link">Delete</a>
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
            <th>Topic ID</th>
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

  // ❌ SQL injection possible via id
  const sql = `UPDATE users SET status = 'banned' WHERE id = ${id}`;
  db.run(sql, (err) => {
    if (err) return res.send("DB error");
    res.redirect("/admin/panel?role=admin");
  });
});

app.get("/admin/user/unban", (req, res) => {
  const roleParam = req.query.role;
  const id = req.query.id;

  if (roleParam !== "admin") return res.send("Access denied.");

  const sql = `UPDATE users SET status = 'active' WHERE id = ${id}`;
  db.run(sql, (err) => {
    if (err) return res.send("DB error");
    res.redirect("/admin/panel?role=admin");
  });
});

app.get("/admin/user/mod", (req, res) => {
  const roleParam = req.query.role;
  const id = req.query.id;

  if (roleParam !== "admin") return res.send("Access denied.");

  const sql = `UPDATE users SET role = 'moderator' WHERE id = ${id}`;
  db.run(sql, (err) => {
    if (err) return res.send("DB error");
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
    if (err) return res.send("DB error");
    res.redirect("/admin/panel?role=admin");
  });
});

app.get("/admin/comment/warn", (req, res) => {
  const roleParam = req.query.role;
  const id = req.query.id;

  if (roleParam !== "admin") return res.send("Access denied.");

  const sql = `UPDATE comments SET status = 'warned' WHERE id = ${id}`; // ❌ SQLi
  db.run(sql, (err) => {
    if (err) return res.send("DB error");
    res.redirect("/admin/panel?role=admin");
  });
});

// ---------- START SERVER ----------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable app running on http://localhost:${PORT}`);
});
