import json
import sys
import hashlib
import requests
import urllib.parse
import socket

def perform_handshake(peer_ip, peer_port, infohash, peer_id):
    try:
        # Ensure peer_id is bytes
        peer_id = peer_id.encode()

        # Create the handshake message
        pstr = b"BitTorrent protocol"
        pstrlen = len(pstr)
        reserved = b'\x00' * 8
        handshake_msg = bytes([pstrlen]) + pstr + reserved + infohash + peer_id

        # Create a TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to the peer
            sock.connect((peer_ip, int(peer_port)))
            
            # Send the handshake
            sock.sendall(handshake_msg)
            
            # Receive the handshake response
            response = sock.recv(68)  # The handshake message is 68 bytes long
            
            # Extract the peer ID from the response
            if len(response) < 68:
                raise ValueError("Invalid handshake response length")
            
            received_peer_id = response[-20:]
            
            # Print the hexadecimal representation of the received peer ID
            print("Peer ID:", received_peer_id.hex())
    
    except Exception as e:
        print(f"An error occurred: {e}")



def encode_bencode(value):
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    elif isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    elif isinstance(value, str):
        encoded_str = value.encode()
        return str(len(encoded_str)).encode() + b":" + encoded_str
    elif isinstance(value, list):
        return b"l" + b"".join(encode_bencode(item) for item in value) + b"e"
    elif isinstance(value, dict):
        # Ensure keys are sorted in lexicographical order
        encoded_dict = b"d"
        for key in sorted(value.keys()):
            encoded_key = key.encode() if isinstance(key, str) else key
            encoded_dict += encode_bencode(encoded_key) + encode_bencode(value[key])
        return encoded_dict + b"e"
    else:
        raise TypeError(f"Unsupported type for bencoding: {type(value)}")

def decode_bencode(bencoded_value):
    def decode_next(index):
        if 48 <= bencoded_value[index] <= 57:  # ASCII check for digits '0' to '9'
            colon_index = bencoded_value.find(b":", index)
            length = int(bencoded_value[index:colon_index])
            start = colon_index + 1
            return bencoded_value[start : start + length], start + length
        elif bencoded_value[index] == ord("i"):
            end_index = bencoded_value.find(b"e", index)
            return int(bencoded_value[index + 1 : end_index]), end_index + 1
        elif bencoded_value[index] == ord("l"):
            index += 1
            decoded_list = []
            while bencoded_value[index] != ord("e"):
                value, index = decode_next(index)
                decoded_list.append(value)
            return decoded_list, index + 1
        elif bencoded_value[index] == ord("d"):
            index += 1
            decoded_dict = {}
            while bencoded_value[index] != ord("e"):
                key, index = decode_next(index)
                value, index = decode_next(index)
                decoded_dict[key.decode() if isinstance(key, bytes) else key] = value
            return decoded_dict, index + 1
        else:
            raise ValueError("Invalid Bencode value")
    decoded_value, _ = decode_next(0)
    return decoded_value
def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        with open(sys.argv[2], "rb") as file:
            bencoded_value = file.read()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                # Decode bytes safely; if non-decodable bytes are found, keep them as bytes.
                try:
                    return data.decode()
                except UnicodeDecodeError:
                    return repr(data)
            raise TypeError(f"Type not serializable: {type(data)}")
        # Decode the bencoded data and convert bytes to strings for JSON output.
        decoded_data = decode_bencode(bencoded_value)
        # Print the Tracker URL without extra quotes
        print("Tracker URL: " + decoded_data["announce"].decode())
        # # Print the Length
        print("Length: " + str(decoded_data["info"]["length"]))
        print("Info Hash:", hashlib.sha1(encode_bencode(decoded_data["info"])).hexdigest(),end="\n")
        print("Piece Length:",decoded_data["info"]["piece length"])
        print("Piece Hashes:",end='')
        data = decoded_data["info"]["pieces"]

        for i in range(0, len(data), 20):
            print(data[i:i+20].hex())
    elif command=="peers":
        with open(sys.argv[2], "rb") as file:
            bencoded_value = file.read()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                # Decode bytes safely; if non-decodable bytes are found, keep them as bytes.
                try:
                    return data.decode()
                except UnicodeDecodeError:
                    return repr(data)
            raise TypeError(f"Type not serializable: {type(data)}")
        # Decode the bencoded data and convert bytes to strings for JSON output.
        decoded_data = decode_bencode(bencoded_value)
        url=decoded_data["announce"].decode()
        info_hash=hashlib.sha1(encode_bencode(decoded_data["info"])).digest()
        peerid="12345678912345678912"
        port=6881
        uploaded=0
        downloaded=0
        left=decoded_data["info"]["length"]
        compact=1
        dic={
        "info_hash": info_hash,
        "peer_id": peerid,
        "port": port,
        "uploaded": uploaded,
        "downloaded": downloaded,
        "left": left,
        "compact": compact
    }
        response=requests.get(url,params=dic)
        red=decode_bencode(response.content)
        print(red)
        peers_compact = red["peers"]
        for i in range(0, len(peers_compact), 6):
            ip = ".".join(str(b) for b in peers_compact[i:i+4])
            port = int.from_bytes(peers_compact[i+4:i+6], "big")
            print(f"{ip}:{port}")


    elif command == "handshake":
        with open(sys.argv[2], "rb") as file:
            bencoded_value = file.read()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                try:
                    return data.decode()
                except UnicodeDecodeError:
                    return repr(data)
            raise TypeError(f"Type not serializable: {type(data)}")
        decoded_data = decode_bencode(bencoded_value)
        peer_ip = sys.argv[3].split(':')[0]
        peer_port = sys.argv[3].split(':')[-1]
        info_hash = hashlib.sha1(encode_bencode(decoded_data["info"])).digest()
        perform_handshake(peer_ip, peer_port, info_hash, "00112233445566778899")

        

    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()

