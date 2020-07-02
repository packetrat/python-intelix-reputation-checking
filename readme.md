This project began as a simple script and supporting class file in Python 3 to run a batch query against Sophos' Intelix threat intelligence system for both URI and IP address classifications. That simple script is still here, as is a more complex script that traverses Intelix and whois data to grab a more complete picture of the hosting of sites that have been identified as potential indicators of compromise (IOCs). 

The intelixclient.py file is a modified version of the pip-installable intelix library, which is currently being updated to include IP address reputation support. 

The script and client class require the following additional pip3 components: <ul>
  <li>requests</li>
  <li>json</li>
  <li>base64</li>
  <li>uuid</li>
  <li>os.path</li>
  <li>sys</li> 
  <li>socket</li></ul>
 
Added: domaincheck.py, which provides additional data including domain registrar, ASN number, host, and country code.
This version requires the additional pip3 components:
<li>whois</li>
<li>ipwhois</li>

Todo: create a requirements.txt for pip3 installation

In order for this script to work, you will need <a href="https://aws.amazon.com/marketplace/pp/Sophos-Limited-SophosLabs-Intelix/B07SLZPMCS">Intelix credentials</a>. 
