import intelixclient, sys, socket
#Intelix setup: enter your data here
clientId = "xxxxxxxxxxxxxxxxxxxx"
secret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
i = intelixclient.client(clientId,secret)
i2 = intelixclient.client(clientId,secret)
inputfile = input("Enter filename containing URIs to be checked: ")  
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
        sys.stdout.write(u"{},{},{},{},{}\n".format(url, i.securityCategory, i.productivityCategory, addr1, i2.category))
        sys.stdout.flush()
        opf.write(u"{},{},{},{},{}\n".format(url, i.securityCategory, i.productivityCategory, addr1, i2.category))
        line = f.readline
    except:
        print( url, "is bad")
        line = f.readline
f.close
