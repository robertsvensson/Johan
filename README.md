# Johan
Johan the VBN tool

Johan - the VBN file decoder

Author: robert@artandhacks.se

This tool decodes and reassembles the binary
to it's original state.

Johan can only properly process windows binaries.

Johan likes to get down and boogie on files
quarantined by Symantec Endpoint Encryption 12.1
but will most likely work with other versions as well

Since Symantec decided that it was not only a good idea to
encrypt the quarantined file with xor but to
also throw in two sets of "distortion" bytes in various places,
Johan will do the exact opposite.

Johan will xor the VBN file using 0xA5 as its key, locate
the proper binary starting point and remove the distorting
bytes.
