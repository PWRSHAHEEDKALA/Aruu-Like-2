import os
import base64
import asyncio
import binascii
import json
import requests
import aiohttp
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError

app = Flask(__name__)

# === GitHub configuration for private repo access ===
GITHUB_TOKEN = "GITHUB_TOKEN"
REPO_OWNER = "PWRSHAHEEDKALA"
REPO_NAME = "Aruu-like-2"

# Function to download a file from GitHub if it does not exist locally
def download_file_if_missing(filename, github_path):
    if not os.path.exists(filename):
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3.raw",
        }
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{github_path}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            with open(filename, "w") as f:
                f.write(response.text)
            app.logger.info(f"Downloaded {filename} from GitHub.")
        else:
            raise Exception(f"Failed to download {filename} from GitHub: {response.status_code} - {response.text}")

# Auto-download required protobuf files from the GitHub repo
download_file_if_missing("like_pb2.py", "like_pb2.py")
download_file_if_missing("like_count_pb2.py", "like_count_pb2.py")
download_file_if_missing("uid_generator_pb2.py", "uid_generator_pb2.py")

# Now import the protobuf files
import like_pb2
import like_count_pb2
import uid_generator_pb2

# === GitHub File Fetching (for token files, counter files, etc.) ===
def fetch_file_from_github(file_path):
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.raw",
    }
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        app.logger.error(f"Error fetching file from GitHub ({file_path}): {response.status_code} - {response.text}")
        return None

def update_file_on_github(file_path, new_content):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    get_response = requests.get(url, headers=headers)
    if get_response.status_code != 200:
        app.logger.error(f"Failed to get file {file_path} for update: {get_response.status_code} - {get_response.text}")
        return False
    file_info = get_response.json()
    sha = file_info["sha"]
    new_content_b64 = base64.b64encode(new_content.encode()).decode()
    data = {
        "message": "Update counter",
        "content": new_content_b64,
        "sha": sha
    }
    put_response = requests.put(url, headers=headers, json=data)
    if put_response.status_code in [200, 201]:
        return True
    else:
        app.logger.error(f"Failed to update file {file_path}: {put_response.status_code} - {put_response.text}")
        return False

# === Token Handling Functions ===
def load_tokens(server_name):
    try:
        if server_name == "IND":
            file_path = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            file_path = "token_br.json"
        elif server_name == "ME":
            file_path = "token_bd.json"
        elif server_name == "VN":
            file_path = "token_vn.json"
        else:
            file_path = "token_eu.json"
        file_content = fetch_file_from_github(file_path)
        if file_content:
            tokens_dict = json.loads(file_content)
            # Convert dictionary values to a list (sorted by key, if needed)
            sorted_keys = sorted(tokens_dict.keys(), key=lambda k: int(k))
            return [tokens_dict[k] for k in sorted_keys]
        else:
            raise Exception(f"Failed to fetch {file_path} from GitHub.")
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def get_tokens(server_name="GLOBAL", all=False):
    tokens = load_tokens(server_name)
    if not tokens:
        return [] if all else None
    return tokens if all else random.choice(tokens)

# Counter file functions for tracking token usage ranges
def get_counter(server_name):
    file_map = {"IND": "ind_remain.json", "BR": "br_remain.json", "US": "br_remain.json", 
                "SAC": "br_remain.json", "NA": "br_remain.json", "ME": "Me_remain.json"}
    file_path = file_map.get(server_name, "bd_remain.json")
    content = fetch_file_from_github(file_path)
    if content:
        try:
            data = json.loads(content)
            return int(data.get("counter", 0))
        except Exception as e:
            app.logger.error(f"Error parsing counter from {file_path}: {e}")
            return 0
    return 0

def update_counter(server_name, new_value):
    file_map = {"IND": "ind_remain.json", "BR": "br_remain.json", "US": "br_remain.json", 
                "SAC": "br_remain.json", "NA": "br_remain.json", "ME": "Me_remain.json"}
    file_path = file_map.get(server_name, "bd_remain.json")
    new_data = json.dumps({"counter": new_value})
    return update_file_on_github(file_path, new_data)

def get_token_range_for_server(server_name):
    counter = get_counter(server_name)
    bucket = counter // 30  # Each bucket covers 30 uses
    start = bucket * 100
    end = start + 100
    tokens_all = load_tokens(server_name)
    if not tokens_all:
        return []
    return tokens_all[start:end]

# === Encryption and Protobuf Functions ===
def encrypt_message(plaintext):
    try:
        key_bytes = b'Yg&tc%DEuh6%Zc^8'
        iv_bytes = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

# === Asynchronous HTTP Request Functions ===
async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = get_token_range_for_server(server_name)
        if tokens is None or len(tokens) == 0:
            app.logger.error("Failed to load tokens from the specified range.")
            return None
        # Send 100 requests round-robin using the filtered token range
        for i in range(100):
            token = tokens[i % len(tokens)]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

# === API Request Function for Getting Player Info ===
def make_request(encrypt_val, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt_val)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

# === GitHub File Fetching Endpoint (for debugging) ===
@app.route('/get_file', methods=['GET'])
def get_github_file():
    try:
        file_path = request.args.get("file_path")
        if not file_path:
            return jsonify({"error": "File path is required"}), 400
        content = fetch_file_from_github(file_path)
        if content is None:
            return jsonify({"error": "Failed to fetch file from GitHub"}), 500
        return jsonify({"file_content": content}), 200
    except Exception as e:
        app.logger.error(f"Error fetching file from GitHub: {e}")
        return jsonify({"error": str(e)}), 500

# === Main /like Endpoint ===
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        def process_request():
            app.logger.info(f"Starting request processing for UID: {uid}, Server: {server_name}")
            tokens_all = load_tokens(server_name)
            if tokens_all is None:
                raise Exception("Failed to load tokens.")
            app.logger.info(f"Loaded tokens: {tokens_all}")
            token = tokens_all[0]
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # Retrieve initial player info
            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
                data_before = json.loads(jsone)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            # Perform like requests asynchronously using tokens from a specified bucket/range
            asyncio.run(send_multiple_requests(uid, server_name, url))

            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
                data_after = json.loads(jsone_after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given != 0 else 2
            result = {
                "LikesGivenByAPI": like_given,
                "LikesbeforeCommand": before_like,
                "LikesafterCommand": after_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            app.logger.info(f"Request processed successfully for UID: {uid}. Result: {result}")
            # If likes were given (status 1), update the counter in GitHub
            if status == 1:
                current_counter = get_counter(server_name)
                new_counter = current_counter + 1
                if update_counter(server_name, new_counter):
                    app.logger.info(f"Updated counter for {server_name} to {new_counter}")
                else:
                    app.logger.error(f"Failed to update counter for {server_name}")
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Run the Flask app on port 5001
    app.run(debug=True, host='0.0.0.0', port=5001)
