
#------------------------------------Adham----------------------------------------#
TERMINATING_DATA_LENGTH = 516
TFTP_TRANSFER_MODE = b'netascii'
TFTP_OPCODES = {
    'unknown': 0,
    'read': 1,  # RRQ
    'write': 2,  # WRQ
    'data': 3,  # DATA
    'ack': 4,  # ACKNOWLEDGMENT
    'error': 5}  # ERROR

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('localhost', 69)

def send_rq(filename, mode):
    """
    This function constructs the request packet in the format below.
    Demonstrates how we can construct a packet using bytearray.

        Type   Op #     Format without header

               2 bytes    string   1 byte     string   1 byte
               -----------------------------------------------
        RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
        WRQ    -----------------------------------------------


    :param filename:
    :return:
    """
    request = bytearray()
    # First two bytes opcode - for read request
    request.append(0)
    request.append(1)
    # append the filename you are interested in
    filename = bytearray(filename.encode('utf-8'))
    request += filename
    # append the null terminator
    request.append(0)
    # append the mode of transfer
    form = bytearray(bytes(mode, 'utf-8'))
    request += form
    # append the last byte
    request.append(0)

    print(f"Request {request}")
    sent = sock.sendto(request, server_address)


def send_rq_struct(filename, mode):
    """
    This function constructs the request packet in the format below
    Demonstrates how we can construct a packet using struct.

        Type   Op #     Format without header
               2 bytes    string   1 byte     string   1 byte
               -----------------------------------------------
        RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
        WRQ    -----------------------------------------------

        :param filename:
        :return:
    """
    formatter = '>h{}sB{}sB'  # { > - Big Endian, h - short , s - char, B - 1 byte }
    formatter = formatter.format(len(filename), len('netascii'))
    print(formatter)  # final format '>h8sB8sB'
    request = pack(formatter, TFTP_OPCODES['read'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)

    print(f"Request {request}")
    sent = sock.sendto(request, server_address)


def send_ack(ack_data, server):
    """
    This function constructs the ack using the bytearray.
    We dont change the block number cause when server sends data it already has
    block number in it.

              2 bytes    2 bytes
             -------------------
      ACK   | 04    |   Block #  |
             --------------------
    :param ack_data:
    :param server:
    :return:
    """
    ack = bytearray(ack_data)
    ack[0] = 0
    ack[1] = TFTP_OPCODES['ack']
    print(ack)
    sock.sendto(ack, server)

const (
    OP_RRQ   = uint16(1) #// Read request (RRQ)
    OP_WRQ   = uint16(2) #// Write request (WRQ)
    OP_DATA  = uint16(3) #// Data
    OP_ACK   = uint16(4) #// Acknowledgement
    OP_ERROR = uint16(5) #// Error
)

def server_error(data):
    """
    We are checking if the server is reporting an error
                2 bytes  2 bytes        string    1 byte
              ----------------------------------------
       ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
              ----------------------------------------
    :param data:
    :return:
    """
    opcode = data[:2]
    return int.from_bytes(opcode, byteorder='big') == TFTP_OPCODES['error']


# Map server error codes to messages [ Taken from RFC-1350 ]
server_error_msg = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}


def main():
    arguments = docopt(__doc__)
    filename = arguments['<filename>']
    print(arguments)
    if arguments['--mode'] is not None:
        mode = arguments['--mode']
        if mode.lower() not in TFTP_MODES.keys():
            print("Unknown mode - defaulting to [ netascii ]")
            mode = "netascii"
    else:
        mode = "netascii"

    # Send request
    if arguments['-s']:
        send_rq_struct(filename, mode)
    elif arguments['-b']:
        send_rq(filename, mode)
    else:
        send_rq_struct(filename)

    # Open file locally with the same name as that of the requested file from server
    file = open(filename, "wb")
    while True:
        # Wait for the data from the server
        data, server = sock.recvfrom(600)

        if server_error(data):
            error_code = int.from_bytes(data[2:4], byteorder='big')
            print(server_error_msg[error_code])
            break
        send_ack(data[0:4], server)
        content = data[4:]
        # print(f"Content : {content}")
        file.write(content)
        # print(f"## Data ##: {data[0:4]} : {len(data)}")
        if len(data) < TERMINATING_DATA_LENGTH:
            break


if __name__ == '__main__':
    main()

#------------------------------------Adham----------------------------------------#