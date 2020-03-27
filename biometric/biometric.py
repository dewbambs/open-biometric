import socket
from biometric.defs import *
import struct
from biometric.support import *


class Biometric:

    def __init__(self):
        self.socket_bio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.reply_number = 0  # reply counter
        self.session_id = 0  # session id
        self.last_packet = None
        self.last_reply_code = None
        self.last_session_code = None
        self.last_reply_counter = None
        self.last_payload_data = None
        self.last_reply_size = None
        self.connected_flg = None

    def connect(self, ip_address, dev_port):
        self.socket_bio.connect((ip_address, dev_port))

        # connection command
        # creating packet
        self.send_command(CMD_CONNECT)
        # receive reply
        self.recv_reply()

        # sdk configuration command
        # sets session id
        self.session_id = self.last_session_code

        # set SDKBuild variable of the device
        self.set_device_info('SDKBuild', '1')
        # check reply code
        self.connected_flg = self.recvd_ack()
        return self.connected_flg

    def enable_device(self):
        """
        Enables the device, puts the machine in normal operation.

        :return: Bool, returns True if the device acknowledges
        the enable command.
        """
        self.send_command(CMD_ENABLEDEVICE)
        self.recv_reply()
        return self.recvd_ack()

    def disable_device(self, timer=None):
        """
        Disables the device, disables the fingerprint, keyboard
        and RF card modules.

        :param timer: Integer, disable timer, if it is omitted, an enable
        command must be send to make the device return to normal operation.
        :return: Bool, returns True if the device acknowledges
        the disable command.
        """
        if timer:
            self.send_command(CMD_DISABLEDEVICE, struct.pack('<I', timer))
        else:
            self.send_command(CMD_DISABLEDEVICE)

        self.recv_reply()
        return self.recvd_ack()

    def disconnect(self):
        """
        Terminates connection with the given device.

        :return: Bool, returns True if disconnection command was
        processed successfully, also clears the flag self.connected_flg.
        """
        # terminate connection command
        self.send_command(CMD_EXIT)
        self.recv_reply()

        # close connection and update flag
        self.socket_bio.close()
        self.connected_flg = False

        return self.recvd_ack()

    def add_member(self, uid, name):
        """
        takes parameters uid, permission token, password,
        name, card number, group no, user timezone, timezone 1,
        timezone 2, timezone 3, user id, fixed zeros

        :param uid:
        :param name:
        :return:
        """
        data = create_user(uid, name)
        self.send_command(CMD_USER_WRQ, data)
        self.recv_reply()
        self.refresh_data()

    def create_packet(self, cmd_code, data=None, session_id=None,
                      reply_number=None):
        """
        Creates a packet, given the code and the other optional fields.

        :param cmd_code: Int, Command/reply identifier(see defs.py).
        :param data: Bytearray, data to be placed in the data field
        of the payload.
        :param session_id: Int, session id, if not specified, uses
        the session from connection setup.
        :param reply_number: Int, reply counter, if not specified,
        the reply number is obtained from context.
        :return:
        """
        zk_packet = bytearray(START_TAG)  # fixed tag
        zk_packet.extend([0x00] * 2)  # size of payload
        zk_packet.extend([0x00] * 2)  # fixed zeros
        zk_packet.extend(struct.pack('<H', cmd_code))  # cmd code / reply id
        zk_packet.extend([0x00] * 2)  # checksum field

        # append session id
        if session_id is None:
            zk_packet.extend(struct.pack('<H', self.session_id))
        else:
            zk_packet.extend(struct.pack('<H', session_id))

        # append reply number
        if reply_number is None:
            zk_packet.extend(struct.pack('<H', self.reply_number))
        else:
            zk_packet.extend(struct.pack('<H', reply_number))

        # append additional data
        if data:
            zk_packet.extend(data)

        # write size field
        zk_packet[4:6] = struct.pack('<H', len(zk_packet) - 8)
        # write checksum
        zk_packet[10:12] = struct.pack('<H', checksum16(zk_packet[8:]))

        return zk_packet

    def send_command(self, cmd, data=None):
        """
        Sends a packet with a given command, payload data field
        may be also included.

        :param cmd: Integer, command id.
        :param data: Bytearray, data to be placed in the data field
        of the payload.
        :return: None.
        """
        self.send_packet(self.create_packet(cmd, data))

    def send_packet(self, zkp):
        """
        Sends a given complete packet.

        :param zkp: Bytearray, packet to send.
        :return: None.
        """
        self.socket_bio.send(zkp)

    def recv_reply(self, buff_size=1024):
        """
        Receives data from the device.

        :param buff_size: Int, maximum amount of data to receive,
        if not specified, is set to 1024, also updates the reply number,
        and stores fields of the packet to the attributes:

        - self.last_reply_code
        - self.last_session_code
        - self.last_reply_counter
        - self.last_payload_data

        :return: Bytearray, received data,
        also stored in last_payload_data.
        """
        zkp = self.socket_bio.recv(buff_size)
        zkp = bytearray(zkp)
        self.parse_ans(zkp)
        self.reply_number += 1

    def refresh_data(self):
        """
        Refresh data on device (fingerprints, user info and settings).

        :return: None.
        """
        self.send_command(cmd=CMD_REFRESHDATA)
        self.recv_reply()

    def parse_ans(self, zkp):
        """
        Checks fixed fields of a given packet and extracts the reply code,
        session code, reply counter and data of payload, to the attributes:

        - self.last_reply_code
        - self.last_session_code
        - self.last_reply_counter
        - self.last_payload_data

        :param zkp: Bytearray, packet.
        :return: Bool, returns True if the packet is valid, False otherwise.
        """
        self.last_reply_code = -1
        self.last_session_code = -1
        self.last_reply_counter = -1
        self.last_payload_data = bytearray([])

        # check the start tag
        if not zkp[0:4] == START_TAG:
            print("Bad start tag")
            return False

        # extracts size of packet
        self.last_reply_size = struct.unpack('<I', zkp[4:8])[0]

        # checks the checksum field
        if not is_valid_payload(zkp[8:]):
            print("Invalid checksum")
            return False

        # stores the packet fields to the listed attributes

        self.last_packet = zkp

        self.last_reply_code = struct.unpack('<H', zkp[8:10])[0]

        self.last_session_code = struct.unpack('<H', zkp[12:14])[0]

        self.last_reply_counter = struct.unpack('<H', zkp[14:16])[0]

        self.last_payload_data = zkp[16:]

    def set_device_info(self, param_name, new_value):
        """
        Sets a parameter of the device.

        :param param_name: String, parameter to modify, see the protocol
        terminal spec to see a list of valid param names and valid values.
        :param new_value: String, the new value of the parameters, if it is a
        boolean, it may be given as "0" or "1", integers are given as strings.
        :return: Bool, returns True if the commands were
        processed successfully.
        """
        self.send_command(CMD_OPTIONS_WRQ, bytearray(
            "{0}={1}\x00".format(param_name, new_value), 'ascii'))
        self.recv_reply()
        ack1 = self.recvd_ack()
        self.send_command(CMD_REFRESHOPTION)
        self.recv_reply()
        ack2 = self.recvd_ack()
        return ack1 and ack2

    def recvd_ack(self):
        """
        Checks if the last reply returned an acknowledge packet.

        :return: Bool, True if the last reply was an CMD_ACK_OK reply,
        returns False if otherwise.
        """
        if self.last_reply_code == CMD_ACK_OK:
            return True
        else:
            return False

