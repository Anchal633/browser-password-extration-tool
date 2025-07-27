🔐 Browser Password Extraction Tool

A Windows-based GUI Python tool to **extract and decrypt saved passwords** from Microsoft Edge. The app uses AES decryption techniques on Chromium’s encrypted `Login Data` and provides an interactive interface for searching, filtering, and exporting results.


🚀 Features

- 🔍 **Search/Filter** credentials by URL or username
- 📊 **Sort** results by URL or username
- 🔑 **Decrypt passwords** using the browser’s master key and AES
- 📁 **Export** all credentials to a CSV file
- ⏲️ **Auto timeout** with secure data wipe after inactivity
- 🧹 **Clear sensitive memory** with one click
- 🔐 **Master password prompt** on launch
- 🎛️ **Tkinter GUI** with highlighting and progress bar

📸 GUI Overview

- Keyword filter field
- Sort options (Radio buttons)
- Progress bar during extraction
- Scrolling log area with syntax highlighting
- Buttons for:
  - Extracting & saving passwords
  - Toggling visibility
  - Wiping memory
  - Exiting securely

⚙️ Requirements

- Windows OS
- Python 3.6 or higher

📦 Python Packages

Install dependencies using:

```bash
pip install -r requirements.txt
