# 🔐 Secure Password Checker

A CLI tool to check if your password(s) have been exposed in known data breaches, using the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) **Pwned Passwords API** with built-in **privacy protections** via k-anonymity.

> ✅ No passwords are ever sent in full to the API.  
> ✅ Supports secure interactive input, batch checking, and optional CSV reports.

---

## 🚀 Features

- 🔐 **Privacy-first** (SHA-1 hashing + k-anonymity query)
- 🔁 Check **multiple passwords** at once
- 📁 Load passwords from a **file**
- 🔒 **Secure prompt** mode (no echo in terminal)
- 🧾 Export results to **CSV**
- 📦 CLI interface with `argparse`
- 🧼 Safe output (no full passwords displayed)

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/secure-password-checker.git
cd secure-password-checker
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

🧪 Usage

🔸 Single password (secure prompt)
python main.py --prompt

🔸 Check multiple passwords
python main.py -p hunter2 password123 qwerty

🔸 Check passwords from a file
python main.py -p admin123 welcome123 --csv results.csv

🔸 Export results to CSV
python main.py -p admin123 welcome123 --csv results.csv

🤝 Contributing

Pull requests are welcome! To contribute:

Fork the repo
Create a new branch (git checkout -b feature/new-feature)
Commit your changes
Push and open a pull request
Ideas for future improvements:

Local database of breached passwords
Password strength scoring (zxcvbn or entropy-based)
GUI or web-based version
Docker container

👨‍💻 Author

[Your Name] – Ethical Hacking & Security Automation

GitHub: @r10xM37
