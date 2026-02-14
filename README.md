# God Debloater v1.1

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078d4.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)

**God Debloater** is a professional-grade Windows optimization and debloat tool designed to improve system performance, privacy, and gaming experience. Built with a modern GUI and a safe, modular architecture, it allows users to reclaim control over their Windows environment.

---

## 🚀 Key Features

-   **Modern GUI**: A clean, responsive interface built with WPF.
-   **Safe by Design**: Automatically creates **System Restore Points** before applying major changes.
-   **App Management**: Easily remove bloatware (UWP apps) and standard Win32 programs.
-   **System Optimization**: 
    -   **Privacy Tweaks**: Minimize telemetry and data collection.
    -   **Gaming Tweaks**: Optimize for performance and disable unnecessary game recording services.
    -   **Advanced Tweaks**: Visual effects adjustment, power plan optimization, and temporary file cleaning.
-   **Service Management**: Disable non-essential services categorized by risk level (Safe, Moderate, Risky).
-   **Startup Control**: Manage and disable unnecessary startup items and scheduled tasks.
-   **Rollback System**: Integrated change logging to revert tweaks if needed.

---

## 🛠️ Prerequisites

-   **Windows 10 or 11**
-   **PowerShell 5.1 or higher**
-   **Administrator Privileges** (required to modify system settings)

---

## 📖 How to Use

1.  **Download/Clone** the repository.
2.  Right-click `Run-GodDebloater.bat` and select **Run as Administrator**.
    -   *The launcher will automatically request admin rights if you forget.*
3.  The GUI will open. Use the tabs on the left to navigate through different categories.
4.  **Scan** your system to see current status and recommended optimizations.
5.  Select your desired tweaks and click **Apply**.
6.  **Reboot** your system for all changes to take full effect.

---

## 🛡️ Safety & Disclaimer

> [!IMPORTANT]
> While this tool is designed for safety, modifying system settings always carries a small risk. 
> 1. **Always** let the tool create a Restore Point.
> 2. Avoid disabling services marked as **Risky** unless you are an advanced user.
> 3. This software is provided "as is", without warranty of any kind.

---

## 📦 Project Structure

-   `God-Debloater.ps1`: The main script containing the logic and GUI definition.
-   `Run-GodDebloater.bat`: A convenient launcher that ensures the script runs with the correct permissions and execution policy.
-   `God Debloater/`: Support files and resources.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details (or add one if applicable).

---

## 🤝 Contributing

Feel free to fork this project, submit issues, or create pull requests to help improve Windows for everyone!
