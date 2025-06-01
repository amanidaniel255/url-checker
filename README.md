## Peruzi Salama 🛡️
AI-Powered Link Security Scanner – Web App & Browser Extension

## 📌 Overview
Peruzi Salama is a security-focused project built with Next.js, designed to operate both as a web application and a browser extension. It allows users to scan any URL and determine if the link is malicious or safe, providing detailed insights across various security dimensions.

Whether you're casually browsing or auditing links professionally, Peruzi Salama gives you real-time security feedback and recommendations to stay safe online.

## 🚀 Features
🔍 Real-time URL scanning – Identify phishing, malware, or compromised links.

🔐 SSL/TLS analysis – Checks certificate validity, expiry, and chain of trust.

🧱 Protocol & Cipher Inspection – Reviews if modern and secure protocols are used (e.g., TLS 1.3).

⚠️ Security Vulnerability Detection – Exposes risks and weak headers.

📜 Domain Intelligence – Reputation, age, DNS records, blacklist checks.

📊 Cryptographic Standards – Audits cipher suites and encryption strength.

💡 Security Recommendations – AI-generated advice to improve website safety.

🧩 Browser Extension – Seamlessly scan links while browsing.

## 🌐 Tech Stack
Next.js – Frontend framework

Tailwind CSS – UI styling

Node.js APIs – For background link analysis

Browser Extension APIs – Chrome/Firefox integration

3rd-party APIs – For reputation, DNS, and certificate analysis

🛠️ Local Development & Contribution Guide
✅ Requirements
Node.js (v18 or later)

pnpm (preferred) or npm/yarn

Git

🔧 Installation
Clone the repo

```bash
git clone https://github.com/amanidaniel255/peruziSalama.git
cd peruzi-salama
```
Install dependencies
```bash
pnpm install
```
Run the app locally
```bash
pnpm dev
```
Visit [http://localhost:3000]

## Browser Extension Mode (Optional)
Build and load the extension:

Go to [chrome://extensions]

Enable Developer Mode

Click Load unpacked and select the /extension folder

## 🤝 Contributing
We welcome contributions from developers, security researchers, and UI/UX designers.

### How to contribute:
Fork the repository

Create a branch for your feature/fix:

```bash
git checkout -b feature/your-feature-name
Commit your changes with a clear message
```

Push and open a Pull Request

```bash
git push origin feature/your-feature-name
```
Follow code quality standards and respect the project's security goals.

## 🙌 Acknowledgments
Inspired by the need for safer digital experiences in Tanzania

Uses multiple public and open threat intelligence sources

Built by passionate developers advocating for cyber hygiene

