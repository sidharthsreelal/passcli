# passcli

A terminal-based encryption tool for passwords and files.

## What it does

- Store and encrypt passwords locally
- Encrypt text and image files
- Decrypt stored passwords and files
- All data secured with one master password

## Installation

```bash
git clone https://github.com/yourusername/passcli.git
cd passcli
pip install -r requirements.txt
```

## Usage

```bash
python passcli.py
```

## Warning

Your encryption password cannot be changed or recovered. If you forget it, all encrypted data is permanently lost. There is no reset. Choose a strong password you will remember.

## Data location

All encrypted data is stored in `~/.passcli/`

## License

MIT
