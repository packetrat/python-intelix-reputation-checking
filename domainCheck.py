#/usr/bin/python3
import intelixclient
import sys
import socket
import ipwhois
import whois
import getopt
import logging
# Intelix setup: enter your data here
clientId = "xxxxxxx"
secret = "xxxxxxx"
inputfile = sys.argv[1]
ifile = open( inputfile, 'r')
o = inputfile + '_results.csv'
opf = open( o, 'w') 

    
def getRegistrar(hostName):
    try:
        addrdomain = whois.query(hostName)
        reg = addrdomain.registrar
        return reg
    except:
       return "lookup failed"
     
def getASNdata(hostname1):
   asndata = {'asn':" ",'asn_description':"",'asn_cidr':""}
   try:
       netobj = ipwhois.Net(hostname1)
       netasn = ipwhois.asn.IPASN(netobj)
       netlookup = netasn.lookup(netasn)
       asndata['asn'] = netlookup['asn']
       asndata['asn_description'] = netlookup['asn_description']
       asndata['asn_cidr'] = netlookup['asn_cidr']
       return asndata
   except:
       asndata['asn']= "lookup fail"
       return asndata
    
def checkIPreputation(ipAddress):
    try:
        i = intelixclient.client(clientId,secret)
        i.ip_lookup(ipAddress)
        return i.category
    except:
        d= "failed"
        return d

def checkDomReputation(hostname):
    try:
         i = intelixclient.client(clientId,secret)
         i.url_lookup(hostname)
         return {'seccat': i.securityCategory, 'prodcat':  i.productivityCategory}
    except:
        return {'seccat':"failed", 'prodcat':"failed"}
           

def main():
    print ('Input file is ', inputfile,".  Output will be to ", inputfile, "_results.csv")
    
    count = 0
    while True:
        count += 1
        line = ifile.readline()
        if not line:
            break
        servername = line.strip()
        try:
            addr1 = socket.gethostbyname(servername)
            netresult = getASNdata(addr1)
            domainReg = getRegistrar(servername)
            dr = checkDomReputation(servername)
            ir =checkIPreputation(addr1)
            sys.stdout.write(u"{},{},{},{},{},{},{},{},{}\n".format(servername, dr['seccat'], dr['prodcat'], addr1, ir, netresult['asn'], netresult['asn_description'], netresult['asn_cidr'], domainReg))
            sys.stdout.flush()
            opf.write(u"{},{},{},{},{},{},{},{},{}\n".format(servername, dr['seccat'], dr['prodcat'], addr1, ir, netresult['asn'], netresult['asn_description'], netresult['asn_cidr'], domainReg))
            line = ifile.readline
        except:
           sys.stdout.write(u"{},is down\n".format(servername))
           sys.stdout.flush()
           opf.write(u"{},is down \n".format(servername))
           line = ifile.readline
           
main()
