
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
