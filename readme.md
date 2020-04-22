This is a simple script and supporting class file in Python 3 to run a batch query against Sophos' Intelix threat intelligence system for both URI and IP address classifications. The intelixclient.py file is a modified version of the pip-installable intelix library, which is currently being updated to include IP address reputation support. 

The script and client class require the following additional pip3 components:
requests
json
base64
uuid
os.path
sys 
socket

Todo: create a requirements.txt for pip3 installation

In order for this script to work, you will need <a href="https://aws.amazon.com/marketplace/pp/Sophos-Limited-SophosLabs-Intelix/B07SLZPMCS">Intelix credentials</a>. 