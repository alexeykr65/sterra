#!/usr/bin/env python
#
# Generate configure files for S-Terra
#
# alexeykr@gmail.com
#
import sys
import argparse
import string
import re
import random
#from colorama import Fore, Style
#import paramiko

description = "sterra: Generate IPSec configuration for S-Terra from source data"
epilog = "ciscoblog.ru"

listParamConfig = ['internal_interface','internal_lan','external_interface']
flagDebug = int()
sterraConfig = dict()
flagFullMesh = 0
flagCentral = 1


fileName = ""
keyPreShare = ""
nameInterface = ""

isakmpPolicy = [
    'crypto isakmp policy 1',
    ' encr gost',
    ' hash gost',
    ' authentication pre-share',
    ' group vko '
]

cryptoIsakmp = [
'crypto isakmp key ',
'need!!!!',
' address '    
]

cryptoMaps = [
'crypto map CRYPTO-MAP  ', 
' match address  ',
' set transform-set CTS-GOST-IMIT ',
' set pfs vko',
' set peer ',
]


def password_gen():
    lower_case_letter = random.choice(string.ascii_lowercase)
    upper_case_letter = random.choice(string.ascii_uppercase)
    number = random.choice(string.digits)
    other_characters = [
        random.choice(string.ascii_letters + string.digits)
        for index in range(random.randint(10, 30))
    ]

    all_together = [lower_case_letter, upper_case_letter] + other_characters

    random.shuffle(all_together)

    return ''.join(all_together)

def cmdArgsParser():
    global fileName, keyPreShare, nameInterface, flagDebug, flagFullMesh
    if flagDebug > 0: print "Analyze options ... "
    parser = argparse.ArgumentParser(description=description, epilog=epilog)    
    parser.add_argument('-f', '--file', help='File name with source data', dest="fileName", default = 'sterra.conf')
    parser.add_argument('-k', '--key', help='Key Preshare for crypto isakmp', dest="keyPreShare", default="")  
    parser.add_argument('-i', '--interface', help='Name of interfaces (default GigabitEthernet)', action="store",  dest="nameInterface", default="GigabitEthernet")
    parser.add_argument('-d', '--debug', help='Debug information view(default =1, 2- more verbose', dest="flagDebug", default=1)
    parser.add_argument('-m', '--mesh', help='Enable Full Mesh(default = disable', action="store_true")  
    
    arg = parser.parse_args()
    fileName = arg.fileName
    nameInterface = arg.nameInterface
    flagDebug = int(arg.flagDebug)
    if arg.mesh:
        flagFullMesh = 1
    else:
        flagFullMesh = 0
    
    print "flagDebug :" + str(flagDebug)
    
    if arg.keyPreShare == "":
        keyPreShare = password_gen()
    else:
        keyPreShare = arg.keyPreShare
    
    
def invertIpMask(stMsk):
    invMsk = ""
    flagLastOctet = 0
    for octetIP in stMsk.split('.'):
        invMsk += str((255-int(octetIP)))
        flagLastOctet +=1
        if flagLastOctet != 4: invMsk +='.'
    return invMsk
           
def fileConfigAnalyze():
    if flagDebug > 0: print "Analyze source file : " + fileName +" ..."
    f = open(fileName, 'r')
    numSterra = 0
    
    dictSterra = dict()
    flagBeginSterra = 0
    for sLine in f:
        if re.match("#!(.*)$", sLine, re.IGNORECASE):
            
            if flagBeginSterra: sterraConfig[nameSterra] = dictSterra
            nameSterra = re.match("#!(.*)$", sLine, re.IGNORECASE).group(1).strip()
            
            if flagDebug > 2: print " Name sterra:" + nameSterra + "   length: " + str(len(nameSterra))
            if flagDebug > 2: print " Number sterra: " + str(numSterra)
            if flagDebug > 2: print " Dictionary : " + str(dictSterra)
            
            dictSterra = dict()
            flagBeginSterra = 1
            numSterra += 1
            if flagFullMesh == 0:
                dictSterra['central'] = numSterra
            else:
                dictSterra['central'] = 1
        for nameParam in listParamConfig:
            if re.search(nameParam, sLine, re.IGNORECASE):
                sArr = sLine.split('=')
                dictSterra[nameParam] = sArr[1].strip()
                if flagDebug > 2: print " List Array : " + str(sArr[1])
                if flagDebug > 2: print " Dictionary : " + str(dictSterra)
        
    f.close()
    if flagBeginSterra: sterraConfig[nameSterra] = dictSterra
    if flagDebug > 1: print " Sterra Configuration : " + str(sterraConfig)
    
def createConfigFile():
    if flagDebug > 0: print "Create Configuration Files ... "
    flagCentral = 1
    # Create Configuration file
    for nameSterra in sterraConfig:
        print "=========================" + " Name file: " + nameSterra+" ============================"
        fw = open("config_"+nameSterra+'.txt','w')
        fw.write("hostname " + nameSterra + "\n\n")
        # Isakmp Policy create 
        for sLine in isakmpPolicy:
            fw.write(sLine+"\n")
        fw.write("\n")
        
        # crypto key create
        if flagDebug > 0: print "Create crypto key  ... "
        cryptoIsakmp[1] = keyPreShare
        for remoteName in sterraConfig:
            if nameSterra != remoteName:
                if (sterraConfig[remoteName]['central'] == 1) or (sterraConfig[nameSterra]['central'] == 1):
                    if flagDebug > 1: print " Remote name: " + remoteName + "  Local Name : " + nameSterra
                    if flagDebug > 1: print " Remote address: " + str(sterraConfig[remoteName]['external_interface'].split('/')[0])
                    for sLine in cryptoIsakmp:
                        fw.write(sLine)
                    fw.write(str(sterraConfig[remoteName]['external_interface'].split('/')[0]))

                    fw.write("\n")
        fw.write("\n")
        fw.write("crypto ipsec transform-set CTS-GOST-IMIT esp-gost28147-4m-imit\n\n")

        # Access-list create
        if flagDebug > 0: print "Create Access-list ..."
        
        for remoteName in sterraConfig:
            if (nameSterra != remoteName):
                if (sterraConfig[remoteName]['central'] == 1) or (sterraConfig[nameSterra]['central'] == 1):
                    fw.write("! From "+ nameSterra + " to " + remoteName + " \n")
                    fw.write("ip access-list extended ACL-CRYPTO-" + remoteName.upper())
                    fw.write("\n")
                    
                    if flagDebug > 1: print " Remote name: " + remoteName + "  Local Name : " + nameSterra
                    if flagDebug > 1: print " Remote address : " + str(sterraConfig[remoteName]['internal_lan'])
                    if flagDebug > 1: print " Local address  : " + str(sterraConfig[nameSterra]['internal_lan'])
                    for ipAddressLocal in sterraConfig[nameSterra]['internal_lan'].split(','):
                        for ipAddressRemote in sterraConfig[remoteName]['internal_lan'].split(','):
                            if flagDebug > 1: print " IP address Local  : " + str(ipAddressLocal.split('/')[0]) + " Mask : "+str(ipAddressLocal.split('/')[1]) + " invMask "+invertIpMask(str(ipAddressLocal.split('/')[1]))
                            if flagDebug > 1: print " IP address Remote : " + str(ipAddressRemote.split('/')[0]) + " Mask : "+str(ipAddressRemote.split('/')[1]) + " invMask "+invertIpMask(str(ipAddressRemote.split('/')[1]))
                            fw.write(" permit ip " + str(ipAddressLocal.split('/')[0]) +"  " +  invertIpMask(str(ipAddressLocal.split('/')[1])))
                            fw.write("  " + str(ipAddressRemote.split('/')[0]) + "  " +  invertIpMask(str(ipAddressRemote.split('/')[1])))
                            fw.write("\n")
                    #fw.write(str(sterraConfig[remoteName]['external_interface'].split('/')[0]))
                    fw.write("\n")                
                        
        fw.write("\n")



        
        # crypto MAP create
        if flagDebug > 0: print "Create crypto MAP ... "
        numMaps = 100
        for remoteName in sterraConfig:
            if (nameSterra != remoteName):
                if (sterraConfig[remoteName]['central'] == 1) or (sterraConfig[nameSterra]['central'] == 1):
                    if flagDebug > 1: print " Remote name: " + remoteName + "  Local Name : " + nameSterra
                    cryptoMaps[1] = " match address ACL-CRYPTO-" + remoteName.upper()
                    cryptoMaps[0] = "crypto map CRYPTO-MAP "+ str(numMaps) + " ipsec-isakmp"
                    if flagDebug > 1: print " Remote address: " + str(sterraConfig[remoteName]['external_interface'].split('/')[0])
                    
                    for sLine in cryptoMaps:
                        fw.write("\n" + sLine )
                        
                    fw.write(str(sterraConfig[remoteName]['external_interface'].split('/')[0]))
                    fw.write("\n")
                    numMaps += 100
                        
        fw.write("\n")
        
        # Create external Interface 
        if flagDebug > 0: print "Create Interfaces ... "
        fw.write("\n")
        fw.write("interface "+ nameInterface + "0/0\n")
        fw.write(" ip address "+ str(sterraConfig[nameSterra]['external_interface'].split('/')[0]) + " " + str(sterraConfig[nameSterra]['external_interface'].split('/')[1]) +"\n")
        fw.write(" crypto map CRYPTO-MAP\n")
        fw.write(" no shutdown")
        fw.write("\n\n")
        
        # Create internal Interface 
        fw.write("\n")
        fw.write("interface "+ nameInterface + "0/1\n")
        fw.write(" ip address "+ str(sterraConfig[nameSterra]['internal_interface'].split('/')[0]) + " " + str(sterraConfig[nameSterra]['internal_interface'].split('/')[1]) +"\n")
        fw.write(" no shutdown")
        fw.write("\n\n\n")
            
        fw.write("\n")

        # Create routing
        if flagDebug > 0: print "Create routing ..."
        
        for remoteName in sterraConfig:
            if (nameSterra != remoteName):
                if (sterraConfig[remoteName]['central'] == 1) or (sterraConfig[nameSterra]['central'] == 1):
                    if flagDebug > 1: print " Remote address : " + str(sterraConfig[remoteName]['internal_lan'])
                    if flagDebug > 1: print " Gateway address  : " + str(sterraConfig[nameSterra]['external_interface'])
                    fw.write("! Ip route to " + remoteName + "\n")
                    for ipAddressRemote in sterraConfig[remoteName]['internal_lan'].split(','):
                        if flagDebug > 1: print " IP address Remote : " + str(ipAddressRemote.split('/')[0]) + " Mask : "+str(ipAddressRemote.split('/')[1])
                        fw.write("ip route " + str(ipAddressRemote.split('/')[0]) +"  " +  str(ipAddressLocal.split('/')[1]))
                        fw.write("  " + str(sterraConfig[remoteName]['external_interface'].split('/')[0]))
                        fw.write("\n")
                    #fw.write(str(sterraConfig[remoteName]['external_interface'].split('/')[0]))
                    fw.write("\n")                
                        
        fw.write("\n")


    fw.close()
        
if __name__ == '__main__':
    cmdArgsParser()
    fileConfigAnalyze()
    createConfigFile()
    if flagDebug > 0: print "Complete successful!!! "
    
    sys.exit()
