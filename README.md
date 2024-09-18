
# Bencode and BitTorrent Protocol Utility

This script provides a set of tools to work with Bencoded files and the BitTorrent protocol. It allows users to decode bencoded data, fetch torrent metadata, communicate with peers, and perform BitTorrent handshakes.

## Features
- **Decode Bencode**: Decode Bencoded data and print it in JSON format.
- **Fetch Torrent Info**: Extract torrent metadata such as the tracker URL, info hash, piece hashes, etc.
- **Request Peers**: Fetch peer information from the torrent tracker.
- **BitTorrent Handshake**: Perform the BitTorrent handshake with a specified peer.

## Requirements

- Python 3.x
- Modules:
  - `requests`
  - `hashlib`
  - `socket`
  - `sys`
  - `json`
  - `urllib`

You can install the required Python packages using:
```bash
pip install requests
```

## Usage

### Decode Bencoded Data
To decode bencoded data directly:
```bash
python script.py decode "<bencoded_value>"
```

### Fetch Torrent Info
To extract and display torrent metadata from a `.torrent` file:
```bash
python script.py info <path_to_torrent_file>
```
Output includes:
- Tracker URL
- File Length
- Info Hash
- Piece Length
- Piece Hashes

### Fetch Peers from Tracker
To request peers from the tracker associated with a torrent:
```bash
python script.py peers <path_to_torrent_file>
```
This will print a list of peer IP addresses and ports.

### Perform BitTorrent Handshake
To initiate a BitTorrent handshake with a specific peer:
```bash
python script.py handshake <path_to_torrent_file> <peer_ip:peer_port>
```
This will send a handshake message and display the peer's ID.

## Example Commands

- Decode a bencoded string:
    ```bash
    python script.py decode "d4:infod6:lengthi12345ee"
    ```

- Get torrent file info:
    ```bash
    python script.py info example.torrent
    ```

- Fetch peers:
    ```bash
    python script.py peers example.torrent
    ```

- Perform a handshake:
    ```bash
    python script.py handshake example.torrent 127.0.0.1:6881
    ```

## Error Handling

The script includes basic error handling. If an error occurs during a specific operation (e.g., failed connection to a peer), a relevant message will be printed to the console.

## License
This project is open-source and available under the MIT License.
