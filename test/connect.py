import biometric.biometric as ob
import socket
from biometric.defs import *

bio = ob.Biometric()
bio.connect("192.168.0.201", 4370)
