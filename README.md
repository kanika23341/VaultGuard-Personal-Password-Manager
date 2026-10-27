# VaultGuard: Personal Password Manager
VaultGuard is a personal password manager built to explore secure credential storage, encryption, authentication, and full-stack application development.

## Features
- **Master password:** Create a vault and unlock it using a master password.
- **Encrypted credentials:** Credential data is encrypted before being stored in SQLite.
- **Password verification:** Verify the master password without storing it in plaintext.
- **Session authentication:** Bearer tokens protect vault operations, with a 15-minute inactivity timeout.
- **Credential management:** Create, view, edit, and delete saved credentials.
- **Copy and reveal:** Access saved credential details through the frontend.
- **Local database:** Store vault metadata and encrypted credentials in SQLite.

## Tech Stack
**Backend**
- Python
- FastAPI
- SQLite
- Cryptography

**Frontend**
- React
- Vite
- JavaScript
- CSS
- Lucide React icons

## Project Structure
```text
Password_manager/
├── backend/
│   └── app/
│       ├── api.py
│       ├── crypto.py
│       └── storage.py
├── data/
│   └── vault.db          # Local only
├── frontend/
│   ├── src/
│   ├── package.json
│   └── package-lock.json
├── requirements.txt
├── .gitignore
└── README.md
```

## How to Use

### Prerequisites

- Python 3.11 or a compatible Python version
- Node.js and npm

### 1. Clone the repository

### 2. Set up the backend

Create and activate a virtual environment

Start the API:

```powershell
python -m uvicorn backend.app.api:app --reload
```
The API runs at `http://127.0.0.1:8000`.
API documentation is available at `http://127.0.0.1:8000/docs`.

### 3. Set up the frontend
Open a second terminal:
```powershell
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173/` in your browser.

### 4. Create your vault
If no vault exists, create one through the application using a strong master password of at least 12 characters. Use the same password to unlock it later.

## Running Tests
From the project root, activate the virtual environment and run:

```powershell
python -m pytest
```

## Security Notes
- The master password is not intentionally stored in plaintext.
- Credential records are encrypted before being persisted.
- Session tokens are held in backend memory and expire after inactivity.
- The current implementation is a learning project, not an independently audited password manager.
- The development server and frontend configuration are intended for local development.

Do not store real, high-value credentials in this MVP.
