# 🏗️ WAMP Enterprise Dashboard

A real‑time enterprise dashboard for managing agents, monitoring client‑agent chats, and broadcasting system‑wide updates. Built with a Flask backend, WebSockets (Socket.IO), and a responsive frontend.

---

## 🌟 Features

- **Admin Authentication** – Secure login for administrators.
- **Agent Management** – Add, view, and monitor all active agents.
- **Client Management** – View clients with their assigned agents.
- **Real‑time Chat Monitoring** – See live conversations between agents and clients (via Socket.IO).
- **Broadcast System** – Send instant updates to all connected agents/clients.
- **Dashboard Metrics** – Live stats on active agents, total clients, and messages.
- **Demo Mode** – Environment toggle to prevent accidental production actions.

---

##  Tech Stack

| Layer        | Technology                               |
|--------------|------------------------------------------|
| **Frontend** | HTML5, CSS3, Vanilla JavaScript          |
| **Backend**  | Flask (Python 3.8+)                      |
| **WebSockets**| Flask‑SocketIO (real‑time events)        |
| **Database** | SQLite (development) / PostgreSQL (prod) |
| **ORM**      | SQLAlchemy                               |
| **Hosting**  | Render / PythonAnywhere (backend) + GitHub Pages (frontend, optional) |

---

##  Installation

### 1. Clone the repository
```bash
git clone https://github.com/ravenj-png/raven-terazzo.git
cd raven-terazzo
