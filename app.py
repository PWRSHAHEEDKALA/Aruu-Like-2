from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

# Load tokens dynamically
def load_tokens(server_name):
    try:
        token_file = {
            "IND": "token_ind.json",
            "BR": "token_br.json",
            "US": "token_br.json",
            "SAC": "token_br.json",
            "NA": "token_br.json"
        }.get(server_name, "token_bd.json")

        with open(token_file, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

# Encrypt the message
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

# Create Protobuf message
def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

# Validate token before using
def check_token_validity(token):
    headers = {'Authorization': f'Bearer {token}'}
    try:
        response = requests.get("https://client.ind.freefiremobile.com/CheckToken", headers=headers, timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Send like request
async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 10; ASUS_Z01QD Build/Release)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2019.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

# Send multiple requests using all tokens
async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None
        tokens = load_tokens(server_name)
        if tokens is None:
            return None

        valid_tokens = [t["token"] for t in tokens if check_token_validity(t["token"])]
        if not valid_tokens:
            return None

        tasks = []
        for token in valid_tokens:
            tasks.append(send_request(encrypted_uid, token, url))
            await asyncio.sleep(0.5)  # Delay to prevent rate limiting

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

# Create UID protobuf
def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

# Encrypt UID
def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

# Fetch player info
def make_request(encrypt, server_name, token):
    try:
        url_map = {
            "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
            "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        }
        url = url_map.get(server_name, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 10; ASUS_Z01QD Build/Release)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2019.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        return decode_protobuf(response.content.hex())
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

# Decode Protobuf response
def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(bytes.fromhex(binary))
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None

# Like API Route
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        def process_request():
            tokens = load_tokens(server_name)
            if not tokens:
                raise Exception("Failed to load tokens.")

            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if not encrypted_uid:
                raise Exception("Encryption failed.")

            before = make_request(encrypted_uid, server_name, token)
            before_like = int(json.loads(MessageToJson(before)).get('AccountInfo', {}).get('Likes', 0))

            url_map = {
                "IND": "https://client.ind.freefiremobile.com/LikeProfile",
                "BR": "https://client.us.freefiremobile.com/LikeProfile",
                "US": "https://client.us.freefiremobile.com/LikeProfile",
                "SAC": "https://client.us.freefiremobile.com/LikeProfile",
                "NA": "https://client.us.freefiremobile.com/LikeProfile"
            }
            url = url_map.get(server_name)

            asyncio.run(send_multiple_requests(uid, server_name, url))

            after = make_request(encrypted_uid, server_name, token)
            after_like = int(json.loads(MessageToJson(after)).get('AccountInfo', {}).get('Likes', 0))

            return {
                "LikesGivenByAPI": after_like - before_like,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "status": 1 if after_like > before_like else 2
            }

        return jsonify(process_request())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)