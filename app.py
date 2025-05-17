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

app = Flask(name)

def load_tokens(server_name):
    try:
        if server_name == "IND":
            file_path = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA", "ME", "EU"}:
            file_path = "token_bd.json"
        else:
            file_path = "token_br.json"

        with open(file_path, "r") as f:
            return json.load(f)
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext: bytes) -> str:
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv  = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        enc = cipher.encrypt(padded)
        return binascii.hexlify(enc).decode()
    except Exception as e:
        app.logger.error(f"Encryption error: {e}")
        return None

def create_protobuf_message(uid: str, region: str) -> bytes:
    try:
        m = like_pb2.like()
        m.uid = int(uid)
        m.region = region
        return m.SerializeToString()
    except Exception as e:
        app.logger.error(f"Protobuf creation error: {e}")
        return None

async def send_multiple_requests(uid: str, server_name: str, like_url: str) -> int:
    """
    Sends exactly one like-request per token in parallel.
    Returns how many succeeded (status 200).
    """
    try:
        # build encrypted payload
        proto = create_protobuf_message(uid, server_name)
        if not proto:
            return 0
        enc_hex = encrypt_message(proto)
        if not enc_hex:
            return 0
        body = bytes.fromhex(enc_hex)

        tokens = load_tokens(server_name)
        if not tokens:
            return 0

        headers_base = {
            'User-Agent':       "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection':       "Keep-Alive",
            'Accept-Encoding':  "gzip",
            'Content-Type':     "application/x-www-form-urlencoded",
            'Expect':           "100-continue",
            'X-Unity-Version':  "2018.4.11f1",
            'X-GA':             "v1 1",
            'ReleaseVersion':   "OB48"
        }

        success_count = 0
        sem = asyncio.Semaphore(len(tokens))  # adjust concurrency

        async with aiohttp.ClientSession() as session:
            async def one_request(token_obj):
                nonlocal success_count
                headers = headers_base.copy()
                headers['Authorization'] = f"Bearer {token_obj['token']}"
                async with sem:
                    try:
                        async with session.post(like_url, data=body, headers=headers) as resp:
                            if resp.status == 200:
                                success_count += 1
                    except Exception:
                        pass

            # fire one task per token
            await asyncio.gather(*(one_request(t) for t in tokens))
        return success_count

    except Exception as e:
        app.logger.error(f"send_multiple_requests error: {e}")
        return 0

def create_uid_protobuf(uid: str) -> bytes:
    try:
        m = uid_generator_pb2.uid_generator()
        m.saturn_ = int(uid)
        m.garena = 1
        return m.SerializeToString()
    except Exception as e:
        app.logger.error(f"UID protobuf error: {e}")
        return None

def enc(uid: str) -> str:
    pb = create_uid_protobuf(uid)
    return encrypt_message(pb) if pb else None

def decode_protobuf(binary: bytes):
    try:
        info = like_count_pb2.Info()
        info.ParseFromString(binary)
        return info
    except DecodeError as e:
        app.logger.error(f"Protobuf decode error: {e}")
        return None

def make_request(encrypted_hex: str, server_name: str, token: str):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR","US","SAC","NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    headers = {
        'User-Agent':       "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection':       "Keep-Alive",
        'Accept-Encoding':  "gzip",
        'Authorization':    f"Bearer {token}",
        'Content-Type':     "application/x-www-form-urlencoded",
        'Expect':           "100-continue",
        'X-Unity-Version':  "2018.4.11f1",
        'X-GA':             "v1 1",
        'ReleaseVersion':   "OB48"
    }
    try:
        res = requests.post(url, data=bytes.fromhex(encrypted_hex), headers=headers, verify=False)
        return decode_protobuf(res.content)
    except Exception as e:
        app.logger.error(f"make_request error: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server = request.args.get("server_name", "").upper()
    if not uid or not server:
        return jsonify({"error":"UID and server_name required"}), 400

    # load tokens once
    tokens = load_tokens(server)
    if not tokens:
        return jsonify({"error":"Failed to load tokens"}), 500

    try:
        # initial player info
        first_token = tokens[0]['token']
        encrypted = enc(uid)
        before_info = make_request(encrypted, server, first_token)
        before_likes = 0
        if before_info:
            js = MessageToJson(before_info)
            before_likes = int(json.loads(js).get('AccountInfo',{}).get('Likes',0))

        # send one request per token
        like_url = (
            "https://client.ind.freefiremobile.com/LikeProfile"
            if server=="IND" else
            "https://client.us.freefiremobile.com/LikeProfile"
            if server in {"BR","US","SAC","NA"} else
            "https://clientbp.ggblueshark.com/LikeProfile"
        )
        used = asyncio.run(send_multiple_requests(uid, server, like_url))

        # final player info
        after_info = make_request(encrypted, server, first_token)
        after_likes = 0; player_uid=uid; nick=""
        if after_info:
            js = MessageToJson(after_info)
            data = json.loads(js).get('AccountInfo',{})
            after_likes = int(data.get('Likes',0))
            player_uid = int(data.get('UID',uid))
            nick = data.get('PlayerNickname','')

        return jsonify({
            "UID": player_uid,
            "PlayerNickname": nick,
            "LikesbeforeCommand": before_likes,
            "LikesafterCommand": after_likes,
            "LikesGivenByAPI": after_likes - before_likes,
            "status": 1 if (after_likes-before_likes)>0 else 2
        })

    except Exception as e:
        app.logger.error(f"handle_requests error: {e}")
        return jsonify({"error":str(e)}), 500

if name == 'main':
    app.run(debug=True, use_reloader=False)
