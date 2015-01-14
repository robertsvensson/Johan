# Johan - the VBN file decoder
#
# Author: robert@artandhacks.se
#
# This tool decodes and reassembles the binary
# to it's original state.
#
# Johan can only properly process windows binaries.
#
# Johan likes to get down and boogie on files
# quarantined by Symantec Endpoint Encryption 12.1
# but will most likely work with other versions as well
#
# Since Symantec decided that it was not only a good idea to
# encrypt the quarantined file with xor but to
# also throw in two sets of "distortion" bytes in various places,
# Johan will do the exact opposite.
#
# Johan will xor the VBN file using 0xA5 as its key, locate
# the proper binary starting point and remove the distorting
# bytes.
#
# 2014-02-22 v 1.0 - support for windows exe files
# 2014-02-27 v 1.1 - added support for jpg,gif,pdf and rtf files
# 2014-11.19 v 1.2 - added support for msi files
# 2014-11-20 v 1.3 - rewrote the binary to text, and vice versa, handling
# 2014-11-24 v 1.4 - rewrote the function for the external xor command


import sys
import os
import binascii
import time
import subprocess
from binascii import *




####### Define functions ###############

def externalXorCommand():
        subprocess.call(['./xor','-s','-o','XOR','-k','0XA5',sys.argv[1]])

#########################################




if (len(sys.argv)) == 3:

        # xor the VBN file using the external tool xor
        externalXorCommand()

        # xor the VBN file using the external tool xor
        # subprocess.call(['./xor','-s','-o','XOR','-k','0XA5',sys.argv[1]])

        # assign variable to open the output file of external xor command
        xorfilename = sys.argv[1]+".XOR.A5"

        # read symantec vbn file
        vbnfilein = open(xorfilename,'rb').read()

        # read symantec vbn file as HEX in upper case
        vbnfilein = hexlify(vbnfilein).upper()

        # convert data to string
        vbnfilein = str(vbnfilein,'UTF-8')


        # assign temp variable and find the matching HEX sequence
        # of the desired output format and substring the results
        temp = ""

        if sys.argv[2] == "exe":
                temp = (vbnfilein[vbnfilein.find("4D5A"):])
        elif sys.argv[2] == "jpg":
                temp = (vbnfilein[vbnfilein.find("FFD8"):])
        elif sys.argv[2] == "rtf":
                temp = (vbnfilein[vbnfilein.find("7B5C"):])
        elif sys.argv[2] == "gif":
                temp = (vbnfilein[vbnfilein.find("4749"):])
        elif sys.argv[2] == "pdf":
                temp = (vbnfilein[vbnfilein.find("2550"):])
        elif sys.argv[2] == "msi":
                temp = (vbnfilein[vbnfilein.find("CFD0"):])
        else:
                print ("Unsupported file format")


        # locate and delete the distorted byte sequence
        temp = temp.replace("F6C6F4FFFF",'')
        temp = temp.replace("F6FFEFFFFF",'')


        if len(temp) < 5:
                print ("Hex byte string is way too short...aborting")
                print ("The current string value is: "+temp)
                exit()



        # convert string back to HEX again"
        outputfile = bytes(temp,'UTF-8')
        outputfile = (binascii.unhexlify(outputfile))



        # get current date and time to name the output file
        dateandtime = time.strftime("%Y%m%d-%H%M.file")



        # write file as payloadout[date].file in the current directory
        payloadout = open(dateandtime,'wb')
        payloadout.write(outputfile)
        payloadout.close()
        print (dateandtime+" written to current directory")

else:

        print ("Johan - the VBN file decoder")
        print ("Version 1.1 - usage:python.exe johan.py [VBNfile] [file format]")
        print ("")
        print ("Currently supported file formats are: exe, jpg, rtf, gif, pdf, msi")
        print ("Example: python.exe johan.ph GH67DF67D.VBN exe")
