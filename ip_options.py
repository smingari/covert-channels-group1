import argparse
import ipaddress
import os.path

from scapy.all import *
from scapy.layers.inet import *


def main() -> None:
    """
    Main method of the ip_options.py script. Requires a variety of user input to run.
    """

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

    # Parsing arguments
    args = parser.parse_args()

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
        # send_message(destination_addr=destination_addr, source_addr=source_addr, file=encoding_file)
    elif args.server:
        print(f'Covert Channel Application!')
        print(f'Server Mode: Listening for data!')
        print(f'Source Host: {source_addr}')
        print(f'Encoding file: {encoding_file}')
        print(f'Covert Channel Method: IP Options')
        # receive_message(source_addr=source_addr, output_file=encoding_file, timeout=args.timeout)

    def encode_to_hex(character: chr) -> int:
        """
        Encodes ASCII characters into a bit integer.
        :param character: To convert into an integer.
        :return: bit integer.
        """
        # TODO implement encoding scheme
        return ord(character)

    def decode_to_ascii(num: int) -> chr:
        """
        Decode integer into ASCII characters.
        :param num: integer.
        :return: ASCII Character.
        """
        # TODO implement decoding scheme

        return ''.join(chr(int(num)))

    def send_message(destination_addr: str, source_addr: str, file) -> None:
        """
        Read a file and send an encoded message through the IP Options field.
        :param destination_addr: Destination address of the packet.
        :param source_addr: Source address of the packet.
        :param file: File to read the message from.
        """
        with open(file, 'r') as buffer:
            while True:
                char = buffer.read(1)
                if not char:
                    break
                print(f'Sending data: {char}')
                encoded_id = encode_to_hex(char)
                send(IP(dst=destination_addr, src=source_addr), verbose=VERBOSE)

    def packet_callback(pkt, source_addr, output_file) -> None:
        """
        Callback method to perform packet filtering using scapy sniff function.
        :param pkt: Packet from sniff stream.
        :param source_addr: Source address of the message.
        :param output_file: File to write message to.
        """
        if IP in pkt and pkt[IP].src == source_addr:
            print(f'Receiving Data: {decode_to_ascii(pkt[IP].option)}')
            with open(output_file, 'a') as buffer:
                buffer.write(f'Receiving Data: {decode_to_ascii(pkt[IP].option)}\n')

    def receive_message(source_addr: str, output_file, timeout: int) -> None:
        """
        Listens for packets from the source address and decodes the encoded message.
        :param source_addr: Source address of the message.
        :param output_file: FIle to write message to.
        :param timeout: Timeout in seconds.
        :return:
        """
        sniff(prn=lambda packet: packet_callback(packet, source_addr, output_file), timeout=timeout)
