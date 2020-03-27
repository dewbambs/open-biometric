import biometric.biometric as ob
import socket
from biometric.defs import *

bio = ob.Biometric()
bio.connect("192.168.0.201", 4370)
bio.disable_device()
bio.add_member(20012, "polo")
bio.enable_device()
bio.disconnect()
