# RTSP Brute Force Tool
### The RTSP Brute Force Tool is a sophisticated utility designed to assess the security of Real Time Streaming Protocol (RTSP) services by systematically testing potential usernames and passwords. It's built with the intention to aid security professionals and educational users in testing and securing RTSP services against unauthorized access.

## Features
URL Parsing: Extracts IP, port, and path from the provided RTSP URL.
Credential Testing: Supports both predefined usernames and dynamic loading from files, alongside extensive password list testing.
Adaptive Timing: Adjusts connection timeouts based on network response, enhancing efficiency.

## Getting Started
### Prerequisites
Ensure you have Python installed on your system. The tool is compatible with Python 3.x. You can download it from Python's official site.

## Installation
Clone the repository to your local machine:


git clone https://github.com/yourusername/rtsp-brute-force-tool.git
cd rtsp-brute-force-tool

## Usage
Run the script from the command line:


python3 ./rtsp_brute_force.py

Follow the on-screen prompts to enter the RTSP URL, username information, and password file path.

## Examples
Test with known username:

Input the RTSP URL: rtsp://192.168.1.143:554/media.sdp
Choose 'yes' for known username and enter 'admin'.
Provide the path to your password list file.
Test with username list:

Input the RTSP URL as above.
Choose 'no' for known username and provide the path to your username list file.
Provide the path to your password list file.
Contributions
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

## Fork the Project
Create your Feature Branch (git checkout -b feature/AmazingFeature)
Commit your Changes (git commit -m 'Add some AmazingFeature')
Push to the Branch (git push origin feature/AmazingFeature)
Open a Pull Request
## License
Distributed under the MIT License. See LICENSE for more information.

## Disclaimer
This tool is for educational and ethical testing purposes only. Usage of this tool for testing websites or servers without prior mutual consent is illegal. The developer will not be held responsible for any misuse or damage caused by this tool.

