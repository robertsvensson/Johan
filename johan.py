import Tkinter
import binascii
import time

from Tkinter import *
from tkMessageBox import *
from binascii import hexlify
from binascii import unhexlify
from tkFileDialog import *

# Import to make main textarea scrollable.
from ScrolledText import *

# Read the VBN file as binary.
def readInfile():
	vbnFilePath = vbnEntry.get()
	infile = open(vbnFilePath,'rb').read()
	return infile

# Attempt to figure out the original file type
# by reading the file suffix as described in the
# VBN file meta data.
#
# It works by filtering out the first 100 characters
# of the VBN file metadata and cutting out the file
# suffix.
def getFileType(infile):
	# Cut out the first 100 characters
	temp = infile[4:100]
	# Find the last slash to indicate the start the malware file name.
	fileNameStart = temp.rfind("\\")
	# Carve out the file name based on the position the last slash.
	temp = temp[fileNameStart+1:]
	# Carve out the characters up, and including, the . to get the windows file suffix.
	temp = temp[temp.find("."):]
	# And strip out all non alpha numeric characters just to be sure that the file suffix
	# is clean.
	temp = filter(str.isalnum, temp)
	fileType = temp
	return fileType
	
# XOR the VBN file with a key of 0xA5 and assign the result to variable binstr.
def getXorData(infile):
	binstr =''
	for i in range(len(infile)):
		binstr += chr(0xA5 ^ ord(infile[i]))
	return binstr

	
# Convert every byte into the corresponding 2-digit hex representation.
def getBinaryStringRepresentation(xordata):
	hexstring = hexlify(xordata).upper()
	return hexstring

# Locate the malware file starting point and delete any data
# found to that point.
# Then remove the distortion sequences F6C6F4FFFF and F6FFEFFFFF added by Symantec.
def getOriginalFileState(hexstring,filetype):
	if filetype == 'exe':
		hexstring = (hexstring[hexstring.find("4D5A"):])
	elif filetype == 'jpg':
		hexstring = (hexstring[hexstring.find("FFD8"):])
	elif filetype == 'jpeg':
		hexstring = (hexstring[hexstring.find("FFD8"):])
	elif filetype == 'rtf':
		hexstring = (hexstring[hexstring.find("7B5C"):])
	elif filetype == 'gif':
		hexstring = (hexstring[hexstring.find("4749"):])
	elif filetype == 'pdf':
		hexstring = (hexstring[hexstring.find("2550"):])
	
	hexstring = hexstring.replace("F6C6F4FFFF",'')
	hexstring = hexstring.replace("F6FFEFFFFF",'')
	
	return hexstring
	
# Convert HEX string back to binary string again.
def setHexBackToBinary(hexstring):
	binstr = bytes(hexstring)
	binstr = (binascii.unhexlify(binstr))
	return binstr

# Get the full VBN file path and write it to the vbnEntry field.
def openFileWindow():
	getVbnFile = askopenfilename(parent=top)
	vbnEntry.delete(0,END)
	vbnEntry.insert(0,getVbnFile)
	

# Get the desired output directory and write it to the VbnOutputDirectory field.
def setVbnOutputDirectory():
	VbnOutputDirectory = askdirectory(parent=top)
	vbnOutputDirectory.delete(0,END)
	vbnOutputDirectory.insert(0,VbnOutputDirectory)
	
def getDateAndTime():
	dateandtime = time.strftime("%Y%m%d-%H%M")
	return dateandtime

# Write VBN back to disc in its original malwareish state.
def writeOutfile(binstr,dateandtime):
	outputDirectory = vbnOutputDirectory.get()
	malware = open(outputDirectory+'/'+dateandtime+'.malware','w+b')
	textPad.insert(INSERT,dateandtime+'.malware written to '+outputDirectory)
	malware.write(binstr)
	malware.close()

# This method will in called when the user clicks the Go Johan! button.
# It's simply a method that calls other methods.
def start():
	infile = readInfile()
	filetype = getFileType(infile)
	xordata = getXorData(infile)
	hexstring = getBinaryStringRepresentation(xordata)
	hexstring = getOriginalFileState(hexstring,filetype)
	binstr = setHexBackToBinary(hexstring)
	dateandtime = getDateAndTime()
	outfile = writeOutfile(binstr,dateandtime)

# Initiate the main window.
top = Tkinter.Tk()
top.title("Johan 2 - The VBN tool")

# GUI components for selecting the VBN input file.
label = Tkinter.Label(top,text="VBN file:")
label.grid(row=0, column=0, padx=5, pady=5, sticky=W)

vbnEntry = Tkinter.Entry(top,width=50)
vbnEntry.grid(row=0, column=1, padx=5, pady=5)

button = Tkinter.Button(top, text="Browse", command = openFileWindow)
button.grid(row=0, column=2, padx=5, pady=5)

# GUI components for selecting the output directory and execution button.
label = Tkinter.Label(top,text="Output directory:")
label.grid(row=2, column=0, padx=5, pady=5, sticky=W)

vbnOutputDirectory = Tkinter.Entry(top,width=50)
vbnOutputDirectory.grid(row=2, column=1, padx=5, pady=5)

button = Tkinter.Button(top, text="Browse", command = setVbnOutputDirectory)
button.grid(row=2, column=2, padx=5, pady=5)

button = Tkinter.Button(top, text="Go Johan!", command = start)
button.grid(row=5, column=1, padx=5, pady=5)

# GUI component for the textarea used for displaying status messages. 
tkwidth = top.winfo_reqwidth()
tkheight = top.winfo_reqheight()

textPad = ScrolledText(top, width=70, height=30)
textPad.grid(row=6, column=0, columnspan=4, padx=5, pady=5)

# GUI component for the bottom footer.
footerlabel = Tkinter.Label(top,text="2015 robert@artandhacks.se GPL2")
footerlabel.grid(row=7, column=0,columnspan=4, padx=5, pady=5)

top.mainloop()
