# Mini Feedback System

A simple self-hosted web application that allows users to:

✨ Create and view public comments  
✨ Login to a basic user dashboard  
✨ Access a simple admin page (with demo accounts)  

This project was built using **Node.js, Express, and SQLite** and includes static front-end pages styled with HTML, CSS, and basic React (CDN-based).

> 📌 This project is created strictly for educational demonstration purposes only.

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 📝 Comment Board | Users can submit and view public comments |
| 🔐 User Login | Basic login page using hardcoded demo accounts |
| 🛠 Admin Panel | View user table (username, password, role) |
| 🎨 Styled UI | Simple modern interface using custom CSS |
| 💾 SQLite In-Memory | Lightweight demo database setup (temporary) |

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Node.js, Express |
| Database | SQLite (in-memory) |
| Frontend | HTML, CSS, Basic React (via CDN) |
| Language | JavaScript |

---

## 📦 Installation & Deployment

### Prerequisites

- **Node.js** (v14 or higher) and **npm** installed
- For Docker deployment: **Docker** and **Docker Compose** installed

### Option 1: Localhost Deployment

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start the application:**
   ```bash
   npm start
   ```
   Or directly:
   ```bash
   node app.js
   ```

3. **Access the application:**
   - Open your browser and navigate to: `http://localhost:3000`
   - The app will be running on port 3000

**Demo Accounts:**
- Admin: `admin` / `admin123`
- User: `alice` / `password`
- Banned User: `bob` / `password`

### Option 2: Docker Deployment

#### Using Docker Compose (Recommended)

1. **Build and start the container:**
   ```bash
   docker-compose up -d
   ```

2. **View logs:**
   ```bash
   docker-compose logs -f
   ```

3. **Stop the container:**
   ```bash
   docker-compose down
   ```

4. **Access the application:**
   - Open your browser and navigate to: `http://localhost:3000`

#### Using Docker directly

1. **Build the Docker image:**
   ```bash
   docker build -t selfhostweb .
   ```

2. **Run the container:**
   ```bash
   docker run -d -p 3000:3000 --name selfhostweb-app selfhostweb
   ```

3. **View logs:**
   ```bash
   docker logs -f selfhostweb-app
   ```

4. **Stop the container:**
   ```bash
   docker stop selfhostweb-app
   docker rm selfhostweb-app
   ```

### ⚠️ Important Notes

- **Database Persistence:** The application uses an in-memory SQLite database (`:memory:`). All data will be lost when the application or container stops/restarts.
- **Port Configuration:** The application runs on port 3000 by default. To change it, modify the `PORT` variable in `app.js` (line 671).
- **Security:** This is a demonstration application with intentional security vulnerabilities for educational purposes. **Do not use in production.**

---

## 🔧 Troubleshooting

- **Port already in use:** Change the port in `app.js` or stop the service using port 3000
- **Dependencies not installing:** Ensure Node.js and npm are properly installed
- **Docker build fails:** Make sure Docker is running and you have sufficient disk space


