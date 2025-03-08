from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

API_KEY = "@Mohd1like"  # Added API key

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

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

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_like_request(uid, server_name):
    url = f"https://aruu-like-2.vercel.app/like?uid={uid}&server_name={server_name}&key={API_KEY}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                return {"error": f"API request failed with status {response.status}"}
    except Exception as e:
        return {"error": str(e)}

def get_player_info(uid, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        
        encrypted_uid = encrypt_message(str(uid).encode())
        if not encrypted_uid:
            return None
        
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
        response = requests.post(url, data=bytes.fromhex(encrypted_uid), headers=headers, verify=False)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        app.logger.error(f"Error in get_player_info: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_like():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        tokens = load_tokens(server_name)
        if not tokens:
            return jsonify({"error": "Failed to load tokens"}), 500
        
        token = tokens[0]["token"]
        player_info_before = get_player_info(uid, server_name, token)

        if not player_info_before:
            return jsonify({"error": "Failed to retrieve player info"}), 500

        player_name = player_info_before.get("nickname", "Unknown Player")
        likes_before = player_info_before.get("likes", 0)

        like_response = asyncio.run(send_like_request(uid, server_name))

        if "error" in like_response:
            return jsonify(like_response), 500

        player_info_after = get_player_info(uid, server_name, token)
        likes_after = player_info_after.get("likes", 0) if player_info_after else likes_before

        response_data = {
            "message": "Like sent successfully",
            "player_name": player_name,
            "uid": uid,
            "likes_before": likes_before,
            "likes_after": likes_after,
            "likes_given": likes_after - likes_before
        }

        return jsonify(response_data)

    except Exception as e:
        app.logger.error(f"Error processing like request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)