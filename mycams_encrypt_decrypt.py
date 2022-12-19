from base64 import b64decode, b64encode
import hashlib
import hmac
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from datetime import datetime, timedelta



class AESCBC:
    def __init__(self, key, iv):
        self.key = hashlib.sha256(key.encode("utf-8")).hexdigest()
        if len(self.key) > 32:
            self.key = self.key[:32].encode("utf-8")
        self.iv = bytes(iv, "utf-8")

    def encrypt(self, data):
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return (
            b64encode(self.cipher.encrypt(pad(data.encode("utf-8"), AES.block_size)))
            .decode("utf-8")
            .replace("+", "-")
            .replace("/", "_")
        )

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(self.cipher.decrypt(raw), AES.block_size).decode("utf-8")



def create_signature_mycams():
    try:
        CLIENT_ID = "client_id"
        SECRET_KEY = "secret_key"
        hmac_key = "hmac_key"
        DATE_TIMESTAMP = datetime.now().strftime("%Y%m%d%H%M%S")

        SIGNATURE = "{}::{}::{}".format(CLIENT_ID, SECRET_KEY, DATE_TIMESTAMP)

        expected_signature = hmac.new(
            digestmod="sha256",
            msg=bytes(SIGNATURE, "utf-8"),
            key=bytes(hmac_key, "utf-8"),
        )
        return DATE_TIMESTAMP, expected_signature.hexdigest()
    except Exception as e:
        print(e.args)