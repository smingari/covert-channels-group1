import argparse
import ipaddress
import os.path

from scapy.all import *
from scapy.layers.inet import *


def main() -> None:
    """
    Main method of the ip_options.py script. Requires a variety of user input to run.
    """
    global VERBOSE
    destination_addr = ''
    source_addr = ''
    parser = argparse.ArgumentParser(description="A basic script with user input flags")

    # Adding arguments
    parser.add_argument('-s', '--source', type=str, help='The source IP address')
    parser.add_argument('-d', '--destination', type=str, help='The destination IP address')
    parser.add_argument('-f', '--file', type=str, help='File name read or write the message to')
    parser.add_argument('-c', '--client', action='store_true', help='Machine sending the message')
    parser.add_argument('-r', '--server', action='store_true', help='Machine receiving the message')
    parser.add_argument('-t', '--timeout', type=int, default=60,
                        help='Time out for receiving a message. Defaults to 60s.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode.')
    parser.add_argument('-k', '--key', type=int, help='The secure key', default=0)

    # Parsing arguments
    args = parser.parse_args()
    VERBOSE = args.verbose


    if args.client and (args.source is None or args.destination is None):
        parser.error("--client requires --source and --destination")

    if args.server and (args.source is None):
        parser.error("--server requires --source")

    if not args.server and not args.client:
        parser.error("You must select a valid mode of either --server or --client")

    # Validate valid IP addr and then convert back to string
    if args.destination is not None:
        destination_addr = str(ipaddress.ip_address(args.destination))
    if args.source is not None:
        source_addr = str(ipaddress.ip_address(args.source))

    key = args.key
    encoding_file = args.file
    VERBOSE = args.verbose

    if args.client:
        if not os.path.isfile(encoding_file):
            print(f'Error invalid file {args.file}. Please use a valid file!')
            exit(1)
        print(f'Covert Channel Application!')
        print(f'Client Mode: Sending data!')
        print(f'Destination Host: {destination_addr}')
        print(f'Source Host: {source_addr}')
        print(f'Encoding file: {encoding_file}')
        print(f'Covert Channel Method: IP Options')
        send_message(destination_addr=destination_addr, source_addr=source_addr, key=key, file=encoding_file)
    elif args.server:
        print(f'Covert Channel Application!')
        print(f'Server Mode: Listening for data!')
        print(f'Source Host: {source_addr}')
        print(f'Encoding file: {encoding_file}')
        print(f'Covert Channel Method: IP Options')
        receive_message(source_addr=source_addr, output_file=encoding_file, key=key, timeout=args.timeout)


def caesar_cipher(character: chr, key: int) -> str:
    """
    :param character: Character to perform cipher on.
    :param key: Key for caesar cipher.
    :return: encoded character.
    """
    ciphered = ""
    if key < 0:
        raise Exception("invalid key.")
    key = key % 26
    # If there is no character don't use the NULL character but the ""
    if ord(character) == 00:
        ciphered += ""
    # Special characters that do not get ciphered (".", ",", " ")
    elif ord(character) in [00, 32, 33, 44, 46]:
        ciphered += chr(ord(character))
    elif character.islower():
        ciphered += chr((ord(character) + key - 97) % 26 + 97)
    else:
        ciphered += chr((ord(character) + key - 65) % 26 + 65)
    return ciphered


def encode_to_hex(characters: str, key: int) -> hex:
    """
    Encodes ASCII characters into bytes.
    :param characters: A string of two characters.
    :param key: key for the cipher.
    :return: byte representation after performing a caesar cipher.
    """
    ciphered = ''
    for character in characters:
        ciphered += caesar_cipher(character, key)
    return str.encode(ciphered)


def decode_to_ascii(cipher: hex, key: int) -> str:
    """
    Decode integer into ASCII characters.
    :param cipher: the encoded data.
    :param key: the key for the cipher
    :return: 2 ASCII Characters.
    """
    decode = ''
    characters = bytes.fromhex(cipher).decode("utf-8")
    for character in characters:
        decode += caesar_cipher(character, 26 - (key % 26))
    return decode


def send_message(destination_addr: str, source_addr: str, key: int, file) -> None:
    """
    Read a file and send an encoded message through the IP Options field.
    :param destination_addr: Destination address of the packet.
    :param source_addr: Source address of the packet.
    :param key: Secret key
    :param file: File to read the message from.
    """
    index = 0
    with open(file, 'r') as buffer:
        while True:
            char = buffer.read(2)
            if not char:
                break
            print(f'Sending data: {char}')
            encoded_id = encode_to_hex(char, key)
            encode_options = IPOption(copy_flag=1, optclass=0, option=8, length=4, value=encoded_id)
            encoded_packet = IP(dst=destination_addr, src=source_addr, id=0x1011, options=encode_options)
            send(encoded_packet, verbose=VERBOSE)
            index += 1


def packet_callback(pkt, source_addr, key, output_file: None) -> None:
    """
    Callback method to perform packet filtering using scapy sniff function.
    :param pkt: Packet from sniff stream.
    :param source_addr: Source address of the message.
    :param key: Secret key
    :param output_file: File to write message to.
    """
    if IP in pkt and pkt[IP].src == source_addr:
        if pkt[IP].options:
            for option in pkt[IP].options:
                if option.option == 8:
                    encoded_data = option.security
                    try:
                        decoded_data = decode_to_ascii(hex(encoded_data).lstrip("0x"), key)
                        print(f'Decoding: {decoded_data}')
                        if output_file is not None:
                            with open(output_file, 'a') as buffer:
                                buffer.write(decoded_data)
                    except Exception as e:
                        print(f"Error decoding data: {e}")


def receive_message(source_addr: str, key: int, output_file: None, timeout: int) -> None:
    """
    Listens for packets from the source address and decodes the encoded message.
    :param source_addr: Source address of the message.
    :param key: Secret key
    :param output_file: File to write message to.
    :param timeout: Timeout in seconds.
    :return:
    """
    sniff(prn=lambda packet: packet_callback(packet, source_addr, key, output_file), timeout=timeout)


if __name__ == "__main__":
    main()
