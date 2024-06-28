# TOTP Manager

TOTP Manager Python based by Akh4th

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Dependencies](#dependencies)
- [Contributing](#contributing)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/akh4th/python_totp_manager.git
   cd python_totp_manager

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt

3. **Run the Configurator:**
    ```bash
   python3 Configure.py

4. **Compile to EXE (optional):**
   ```bash
   python3 Executable_Generator.py

## Usage

Once you have configured your json file run the main.exe file and authenticate using the same password you provided on the configuration and start managing TOTP locally on your computer.
If you seek to compile the python script into an .exe file simply run the python script 'Executable_Generator'.


## Dependencies
```bash
bcrypt==4.1.3
cryptography==42.0.8
tk==0.1.0
ttkbootstrap==1.10.1
pyotp==2.9.0
```

## Contributing
If you'd like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Make your changes.
4. Commit your changes (git commit -am 'Add feature').
5. Push to the branch (git push origin feature-branch).
6. Create a new Pull Request.
