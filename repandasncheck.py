import intelixclient, sys, socket, ipwhois, whois
#Intelix setup: enter your data here
clientId = "7h0g8929jmqb3vjrlifmkpq67t"
secret = "1ivn19h62fsil3vdie9i6h2un11pnfjl9uh22olq563at0isvu0o"
i = intelixclient.client(clientId,secret)
i2 = intelixclient.client(clientId,secret)
inputfile = input("Enter filename containing URIs to be checked: ")  
f = open( inputfile, 'r')
o = inputfile + '_results.txt'
opf = open( o, 'w')
count = 0
while True:
    count += 1
    line = f.readline()
    if not line:
        break
    url = line.strip()
    try:
        addr1 = socket.gethostbyname(url)
        i.url_lookup(url)
        i2.ip_lookup(addr1)
        netobj = ipwhois.Net(addr1)
        netasn = ipwhois.asn.IPASN(netobj)
        netresult = netasn.lookup(netasn)
        addrdomain = whois.query(url)
        sys.stdout.write(u"{},{},{},{},{},{},{},{},{}\n".format(url, i.securityCategory, i.productivityCategory, addr1, i2.category, netresult['asn'], netresult['asn_description'], netresult['asn_cidr'], addrdomain.registrar))
        sys.stdout.flush()
        opf.write(u"{},{},{},{},{},{},{},{},{}}\n".format(url, i.securityCategory, i.productivityCategory, addr1, i2.category, netresult['asn'], netresult['asn_description'], netresult['asn_cidr'], addrdomain.registrar))
        line = f.readline
    except:
        print( url, "is bad")
        line = f.readline
f.close
