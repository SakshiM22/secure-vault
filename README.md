# 🔐 SecureVault – Secure Access Controlled Vault System

SecureVault is a cybersecurity-focused secure file storage system that allows users to upload, store, and manage files with strong encryption, authentication, and security monitoring. The system ensures confidentiality, integrity, and controlled access to sensitive files.

---

# 🌐 Live Demo

**Live Application:**
[https://secure-vault-s2pw.onrender.com](https://secure-vault-s2pw.onrender.com)

---

# 📌 Features

## 👤 User Features

* Secure user registration and login (JWT authentication)
* Upload encrypted files to secure vault
* View and manage stored files
* Download encrypted files securely
* Delete files from vault
* View storage usage and file statistics

## 🛡️ Security Features

* AES-256 file encryption
* JWT-based authentication and session management
* bcrypt password hashing
* Role-based access control (Admin/User)
* Unauthorized access protection
* Account lock protection after failed attempts

## 👨‍💻 Admin Features

* Admin dashboard with security analytics
* View all users
* Lock / unlock user accounts
* Promote / demote user roles
* Monitor audit logs
* Track system activity

## 📊 Monitoring Features

* Audit logging of all activities
* Login tracking
* File upload and download tracking
* Security event monitoring

---

# 🏗️ Tech Stack

## Frontend

* React.js
* CSS3
* Axios
* React Router

## Backend

* Node.js
* Express.js
* JWT Authentication
* Crypto module (AES encryption)
* Multer (file upload)

## Database

* PostgreSQL

## Deployment

* Render (Backend & Frontend)

---

# 🔐 Security Implementation

SecureVault uses multiple layers of security:

* AES-256 encryption for file protection
* bcrypt for password hashing
* JWT for secure authentication
* Role-based authorization
* Audit logging for monitoring
* Account lock protection

---

# 📁 Project Structure

```
secure-vault-system/
│
├── frontend/
│   ├── src/
│   ├── components/
│   ├── pages/
│   ├── styles/
│
├── backend/
│   ├── src/
│   ├── controllers/
│   ├── routes/
│   ├── middleware/
│   ├── utils/
│   │   └── crypto/fileCrypto.js
│   ├── uploads/
│
├── README.md
```

---

# ⚙️ Installation and Setup

## 1. Clone Repository

```
git clone https://github.com/your-username/secure-vault-system.git
cd secure-vault-system
```

---

## 2. Setup Backend

```
cd backend
npm install
npm start
```

Create `.env` file:

```
PORT=5000
DATABASE_URL=your_postgres_url
JWT_SECRET=your_secret_key
```

---

## 3. Setup Frontend

```
cd frontend
npm install
npm start
```

---

# 🚀 Usage

1. Register a new account
2. Login securely
3. Upload files to encrypted vault
4. Access files securely
5. Admin can monitor system via dashboard

---

# 📊 Security Concepts Implemented

* Encryption (AES-256)
* Authentication (JWT)
* Authorization (Role-based access)
* Audit Logging
* Secure File Storage
* Session Management

---

# 🎯 Applications

SecureVault can be used in:

* Enterprise secure file storage
* Government secure systems
* Healthcare record protection
* Confidential business storage
* Cybersecurity systems

---

# 🔮 Future Enhancements

* Two-Factor Authentication (2FA)
* Cloud storage integration
* Email alerts for suspicious activity
* Malware scanning
* Backup and recovery system

---

# 👩‍💻 Author

**Sakshi Nagesh Modak**
M.Sc.IT Student

