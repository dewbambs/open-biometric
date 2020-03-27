import struct


def create_user(user_id, name):
    data = bytearray([0x00] * 2)  # uid
    data.extend([0x00])  # permission token
    data.extend([0x00] * 8)  # password
    data.extend([0x00] * 24)  # name
    data.extend([0x00] * 4)  # card number
    data.extend([0x00])  # group no
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
    data[46:57] = struct.pack('<9s', str(user_id).encode('utf-8'))

    return data


print(create_user(10006, 'ritesh singh'))
