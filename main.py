from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import base64


def derive_key(passwordParam):
    if type(passwordParam) == str:
        passwordParam = passwordParam.encode('utf-8')
    kdf = Scrypt(  # key derivation function
        salt=b'ABCDEFGHIJKLMNOP',
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
        backend=default_backend()
    )
    deriveKey = kdf.derive(passwordParam)
    key = base64.urlsafe_b64encode(deriveKey)  # + -> -, / -> _
    return key


def encrypt(chunkParam, passwordParam: str):
    key = derive_key(passwordParam)
    fernet = Fernet(key)
    encryptedChunk = fernet.encrypt(chunkParam)
    return encryptedChunk


def decrypt(chunkParam, passwordParam: str):
    key = derive_key(passwordParam)
    fernet = Fernet(key)
    try:
        decryptedChunk = fernet.decrypt(chunkParam)
    except Exception:
        return None
    return decryptedChunk


def encrypt_file(fileNameParam: str, passwordParam: str) -> None:
    with open(fileNameParam, 'rb') as fileObject:
        fileContent = fileObject.read()
        encryptedFileContent = encrypt(fileContent, passwordParam)

    with open(f"{fileNameParam}.enc", 'wb') as fileObject:
        fileObject.write(encryptedFileContent)


def decrypt_file(fileNameParam: str, passwordParam: str) -> None:
    with open(fileNameParam, 'rb') as fileObject:
        nameAndFormats = fileObject.name.split('.')
        name = nameAndFormats[0]
        fileFormat = nameAndFormats[1]
        print(fileObject.name)
        fileContent = fileObject.read()
        decryptedFileContent = decrypt(fileContent, passwordParam)

    if decryptedFileContent is None:
        print('Wrong password!')
    else:
        with open(f"{name}.dec.{fileFormat}", 'wb') as fileObject:
            fileObject.write(decryptedFileContent)


while True:
    command = input("Choose operation type (E/D):  ").upper()
    if command == 'E' or command == 'D':
        break
    else:
        print("Enter 'E' or 'D'.")

while True:
    password = (input("Enter password: "))
    if len(password) > 5:
        break
    else:
        print('Password must be at least 6 character!')

fileName = input("Enter file name that you want to perform action:  ")

if command == 'E':
    encrypt_file(fileName, password)
elif command == 'D':
    decrypt_file(fileName, password)
