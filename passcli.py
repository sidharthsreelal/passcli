import os
import sys
import json
import base64
import getpass
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

dataFolder = Path.home() / ".passcli"
saltFile = dataFolder / "salt.bin"
verifyFile = dataFolder / "verify.enc"
pwdFile = dataFolder / "passwords.enc"
fileLog = dataFolder / "encrypted_files.json"

def makeFolder():
    dataFolder.mkdir(exist_ok=True)
def getKey(pwd, s):
    kdf = Scrypt(salt=s, length=32, n=2**18, r=8, p=1, backend=default_backend())
    k = kdf.derive(pwd.encode())
    return base64.urlsafe_b64encode(k)
def getFernet(pwd, s):
    return Fernet(getKey(pwd, s))
def restart():
    print("\nIncorrect encryption password. Restarting...\n")
    os.execv(sys.executable, [sys.executable] + sys.argv)
def firstSetup():
    print("=" * 60)
    print("WARNING: ENCRYPTION PASSWORD CANNOT BE CHANGED")
    print("=" * 60)
    print()
    print("If you forget your encryption password, all encrypted data")
    print("will be permanently unrecoverable. There is no reset option.")
    print()
    print("The strength of your encryption depends entirely on the")
    print("complexity of your chosen password. Use a strong, unique")
    print("password that you can remember.")
    print()
    print("=" * 60)
    print()
    while True:
        p1 = getpass.getpass("Enter encryption password: ")
        p2 = getpass.getpass("Confirm encryption password: ")
        if p1 == p2:
            if len(p1) < 1:
                print("Password cannot be empty. Try again.\n")
                continue
            break
        print("Passwords do not match. Try again.\n")
    makeFolder()
    s = os.urandom(32)
    with open(saltFile, "wb") as f:
        f.write(s)
    fer = getFernet(p1, s)
    vData = fer.encrypt(b"passcli_verified")
    with open(verifyFile, "wb") as f:
        f.write(vData)
    with open(pwdFile, "wb") as f:
        f.write(fer.encrypt(b"{}"))
    with open(fileLog, "w") as f:
        json.dump([], f)
    print("\nEncryption password set successfully.\n")
def getSalt():
    with open(saltFile, "rb") as f:
        return f.read()
def checkPwd(pwd):
    s = getSalt()
    fer = getFernet(pwd, s)
    try:
        with open(verifyFile, "rb") as f:
            enc = f.read()
        dec = fer.decrypt(enc)
        return dec == b"passcli_verified"
    except InvalidToken:
        return False
def askPwd():
    p = getpass.getpass("Enter encryption password: ")
    if not checkPwd(p):
        restart()
    return p
def loadPwds(pwd):
    s = getSalt()
    fer = getFernet(pwd, s)
    with open(pwdFile, "rb") as f:
        enc = f.read()
    dec = fer.decrypt(enc)
    return json.loads(dec.decode())
def savePwds(pwd, data):
    s = getSalt()
    fer = getFernet(pwd, s)
    enc = fer.encrypt(json.dumps(data).encode())
    with open(pwdFile, "wb") as f:
        f.write(enc)
def loadLog():
    if not fileLog.exists():
        return []
    with open(fileLog, "r") as f:
        return json.load(f)
def saveLog(log):
    with open(fileLog, "w") as f:
        json.dump(log, f, indent=2)
def encryptPwd():
    print("\n--- Encrypt Password ---\n")
    label = input("What is this password for? ")
    val = getpass.getpass("Enter the password value: ")
    masterPwd = askPwd()
    pwds = loadPwds(masterPwd)
    pwds[label] = val
    savePwds(masterPwd, pwds)
    print(f"\nPassword for '{label}' encrypted and stored.\n")
def decryptPwds():
    print("\n--- Decrypt Passwords ---\n")
    masterPwd = askPwd()
    pwds = loadPwds(masterPwd)
    if not pwds:
        print("No passwords stored.\n")
        return
    print("\nStored passwords:\n")
    for lbl, val in pwds.items():
        print(f"{lbl} --> {val}")
    print()
def encryptFile():
    print("\n--- Encrypt File ---\n")
    fp = input("Enter file path: ").strip().strip('"').strip("'")
    p = Path(fp)
    if not p.exists():
        print("File not found.\n")
        return
    if not p.is_file():
        print("Path is not a file.\n")
        return
    masterPwd = askPwd()
    s = getSalt()
    fer = getFernet(masterPwd, s)
    with open(p, "rb") as f:
        raw = f.read()
    encData = fer.encrypt(raw)
    newPath = p.with_suffix(p.suffix + ".enc")
    with open(newPath, "wb") as f:
        f.write(encData)
    log = loadLog()
    absPath = str(newPath.resolve())
    if absPath not in log:
        log.append(absPath)
        saveLog(log)
    print(f"\nFile encrypted: {newPath}\n")
def decryptFile():
    print("\n--- Decrypt File ---\n")
    masterPwd = askPwd()
    while True:
        fp = input("Enter encrypted file path: ").strip().strip('"').strip("'")
        p = Path(fp)
        if not p.exists():
            print("File not found. Try again.\n")
            continue
        if not p.is_file():
            print("Path is not a file. Try again.\n")
            continue
        log = loadLog()
        absPath = str(p.resolve())
        if absPath not in log:
            print("This file was not encrypted by this program. Try again.\n")
            continue
        break
    s = getSalt()
    fer = getFernet(masterPwd, s)
    with open(p, "rb") as f:
        encData = f.read()
    try:
        decData = fer.decrypt(encData)
    except InvalidToken:
        print("Failed to decrypt file.\n")
        return
    if p.suffix == ".enc":
        outPath = p.with_suffix("")
    else:
        outPath = p.with_name(p.stem + "_decrypted" + p.suffix)
    with open(outPath, "wb") as f:
        f.write(decData)
    print(f"\nFile decrypted: {outPath}\n")
def menu():
    while True:
        print("=" * 40)
        print("         PASSWORD ENCRYPTION CLI")
        print("=" * 40)
        print()
        print("1. Encrypt Password")
        print("2. Decrypt Password")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Exit")
        print()
        c = input("Select option: ").strip()
        if c == "1":
            encryptPwd()
        elif c == "2":
            decryptPwds()
        elif c == "3":
            encryptFile()
        elif c == "4":
            decryptFile()
        elif c == "5":
            print("\nGoodbye.\n")
            sys.exit(0)
        else:
            print("\nInvalid option.\n")
def main():
    makeFolder()
    if not saltFile.exists() or not verifyFile.exists():
        firstSetup()
    menu()
if __name__ == "__main__":
    main()
