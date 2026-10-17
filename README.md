# AEGIS-XAI
### AI-Enhanced Guard for Intelligent Security with Explainable AI

AEGIS-XAI is a cybersecurity project exploring AI-assisted network intrusion detection, network traffic monitoring, and explainable security analysis.

The project combines a web-based monitoring dashboard with network traffic capture and machine learning components to help visualize network activity and investigate potential threats.

## 🚀 Project Goals

- Monitor network traffic using TShark.
- Process captured traffic into network flows for security analysis.
- Explore machine learning-based anomaly and intrusion detection.
- Present monitoring information through a web dashboard.
- Support explainable analysis of potential security events.

## ✨ Features

- **Monitoring dashboard:** View network monitoring information.
- **Traffic capture:** Integrate with TShark for packet capture.
- **Flow processing:** Process captured traffic into network flows.
- **Detection components:** Explore machine learning and rule-based security analysis.
- **Security events and alerts:** Review available event and alert information.
- **Threat context:** Organize findings with security-related context.

*Features may depend on local configuration, database connectivity, network permissions, and the current implementation.*

## 🛠️ Technology Stack

- Next.js
- React and TypeScript
- Node.js
- PostgreSQL
- Drizzle ORM
- TShark / Wireshark
- Machine learning and network traffic analysis components

## 📋 Prerequisites

Install and configure:

- Node.js and npm
- PostgreSQL
- Wireshark with TShark available
- Git

A compatible Windows environment with the required network capture permissions is recommended for the current setup.

## ⚙️ Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/ganeshanragesh/AEGIS-XAI.git
cd AEGIS-XAI
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Create a local `.env.local` file in the project root and add the environment variables required by your configuration.

Example database URL format:

```env
DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/DATABASE_NAME
```

Replace the example values with your local database details. Never publish passwords, API keys, or `.env.local`.

### 4. Configure the database

Create your PostgreSQL database and perform the database setup or migration steps required by the project.

### 5. Start the development server

```bash
npm run dev
```

Open http://localhost:3000 in your browser.

The monitoring dashboard is available at:

http://localhost:3000/dashboard/monitor

### 6. Validate the project

```bash
npm run typecheck
npm run build
```

These checks completed successfully in the tested development environment. They do not independently verify every detection feature.

## 🧪 Project Status

AEGIS-XAI is an ongoing cybersecurity learning and development project. Live monitoring behavior, detection accuracy, and model performance should be validated with controlled tests before operational use.

## 🔐 Responsible Use

Use packet capture and network monitoring only on systems and networks you own or are explicitly authorized to test. Follow applicable laws, organizational policies, and privacy requirements.

## 👨‍💻 Author

**Ganeshan Ragesh**

- GitHub: [@ganeshanragesh](https://github.com/ganeshanragesh)
- LinkedIn: [Connect with me on LinkedIn](www.linkedin.com/in/ganeshan-ragesh-a88b3843a)

Interested in cybersecurity, network security, penetration testing, and AI-assisted threat detection.

---

*Built as a cybersecurity and explainable AI learning project.*