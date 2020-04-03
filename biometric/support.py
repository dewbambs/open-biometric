import struct


def checksum16(payload):
    """
    Calculates checksum of packet.

    :param payload: Bytearray, data to which the checksum is going
    to be applied.
    :return: Int, checksum result given as a number.
    """

    chk_32b = 0  # accumulates short integers to calculate checksum
    j = 1  # iterates through payload

    # make odd length packet, even
    if len(payload) % 2 == 1:
        payload.append(0x00)

    while j < len(payload):
        # extract short integer, in little endian, from payload
        num_16b = payload[j - 1] + (payload[j] << 8)
        # accumulate
        chk_32b += num_16b
        j += 2  # increment pointer by 2 bytes

    # adds the two first bytes to the other two bytes
    chk_32b = (chk_32b & 0xFFFF) + ((chk_32b & 0xFFFF0000) >> 16)

    # ones complement to get final checksum
    chk_16b = chk_32b ^ 0xFFFF

    return chk_16b


def is_valid_payload(p):
    """
    Checks if a given packet payload is valid, considering the checksum,
    where the payload is given with the checksum.

    :param p: Bytearray, with the payload contents.
    :return: Bool, if the payload is consistent, returns True,
    otherwise returns False.
    """
    # if the checksum is valid the checksum calculation, without removing the
    # checksum, should be equal to zero

    if checksum16(p) == 0:
        return True
    else:
        return False


def create_user(user_id, name):
    data = bytearray([0x00] * 2)  # uid
    data.extend([0x00])  # permission token
    data.extend([0x00] * 8)  # password
    data.extend([0x00] * 24)  # name
    data.extend([0x00] * 4)  # card number
    data.extend([0x01])  # group no
    data.extend([0x00] * 2)  # user tz
    data.extend([0x00] * 2)  # user tz1
    data.extend([0x00] * 2)  # user tz2
    data.extend([0x00] * 2)  # user tz3
    data.extend([0x00] * 9)  # user id
    data.extend([0x00] * 15)  # fixed zeros

    # insert values
    data[0:2] = struct.pack('<H', user_id)  # update uid
    data[3:11] = struct.pack('<8s', ''.encode('utf-8'))  # set password
    data[11:35] = struct.pack('<24s', name.encode('utf-8'))  # set name
    data[48:57] = struct.pack('<9s', str(user_id).encode('utf-8'))

    return data


def request_data():
    data = bytearray([0x00] * 284)

    # insert values
    request = '~OS=?,ExtendFmt=?,~ExtendFmt=?,ExtendOPLog=?,~ExtendOPLog=?,~Platform=?,~ZKFPVersion=?,WorkCode=?,' \
              '~SSR=?,~PIN2Width=?,~UserExtFmt=?,BuildVersion=?,AttPhotoForSDK=?,~IsOnlyRFMachine=?,CameraOpen=?,' \
              'CompatOldFirmware=?,IsSupportPull=?,Language=?,~SerialNumber=?,FaceFunOn=?,~DeviceName=? '
    data[0:284] = struct.pack('<284s', request.encode('utf-8'))
    return data


def enroll_data(user_id, finger_index, fp_flag=1):
    data = bytearray(struct.pack('<26s', str(user_id).encode('utf-8')))
    data[24] = finger_index
    data[25] = fp_flag
    return data
