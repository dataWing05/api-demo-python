import json
import random
import time
import base64
import requests
import hashlib
from sm2_utils import encrypt_sm2

url = "http://127.0.0.1:8081/api/data/load"

client_id = "your_client_id"
timestamp = str(int(time.time()) * 1000)
nonce = str(random.randint(10000000, 99999999))


def test_get():
    sign_str = client_id + timestamp + nonce
    signature = hashlib.sha256(sign_str.encode('utf-8')).hexdigest()[:32]
    headers = {
        "X-Client-Id": client_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }

    print(headers)

    res = requests.get(url, headers=headers)
    print(res.status_code)
    print(res.text)


def test_post():
    data = {
        "key": "value"
    }
    encrypted_data = encrypt_sm2(json.dumps(data))
    print("base64 decoded encrypted data:", base64.b64decode(encrypted_data))
    sign_str = encrypted_data + client_id + timestamp + nonce
    print(sign_str)
    signature = hashlib.sha256(sign_str.encode('utf-8')).hexdigest()[:32]
    headers = {
        "X-Client-Id": client_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
        "Content-Type": "application/json"
    }

    print(headers)
    print(f"post body data: {encrypted_data}")
    res = requests.post(url, headers=headers, data=encrypted_data)
    print(res.status_code)
    print(res.text)


if __name__ == '__main__':
    test_get()
    test_post()
