import intelixclient, sys, socket, ipwhois, whois, getopt
inputfile = sys.argv[1]
print ('Input file is ', inputfile,".  Output will be to ", inputfile, "_results.csv")
#
#Intelix setup: enter your data here
clientId = "xxxxxxx"
secret = "xxxxxxxxxx"
i = intelixclient.client(clientId,secret)
i2 = intelixclient.client(clientId,secret)
f = open( inputfile, 'r')
o = inputfile + '_results.csv'
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
