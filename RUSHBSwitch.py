import socket
import sys
import threading
import ipaddress


LOCAL_HOST = "127.0.0.1"
BUFFER_SIZE = 1024
RESERVED_BITS = 0
PACKET_SIZE = 1500

# Modes
DISCOVERY_01 = 0x01
OFFER_02 = 0x02
REQUEST_03 = 0x03
ACK_04 = 0x04
ASK_06 = 0x06
DATA_05 = 0x05
READY_07 = 0x07
LOCATION_08 = 0x08
FRAGMENT_0A = 0x0a
FRAGMENT_END_0B = 0x0b


class Connection:
    def __init__(self, type, connection):
        self.type = type
        self.connection = connection
        self.address = LOCAL_HOST


class RUSHBSwitch:
    def __init__(self, switch_type, local_ip, global_ip, latitude, longitude):
        self.switch_type = switch_type
        self.local_ip = local_ip
        self.global_ip = global_ip
        self.latitude = latitude
        self.longitude = longitude
        self.running = False
        self.send_packets = []
        self.recv_packets = []
        self.tcp_sock = None
        self.udp_sock = None
        self.connections = []


    def start(self):
        self.running = True
        # Open necessary ports and display the port number
        if self.switch_type == 'local':
            self.open_udp_port()
            self.open_tcp_port()
        elif self.switch_type == 'global':
            self.open_tcp_port()
        elif self.switch_type == 'mixed':
            self.open_udp_port()
            self.open_tcp_port()
        else:
            print('Invalid switch type')
            sys.exit(1)

        # Determine (virtual) IP address
        if self.switch_type == 'local':
            self.local_ip = self.local_ip.split('/')[0]
            # TODO: remove this one local switches are differentiated from global
            self.global_ip = self.global_ip.split('/')[0]
        elif self.switch_type == 'global':
            self.global_ip = self.global_ip.split('/')[0]
        elif self.switch_type == 'mixed':
            self.local_ip = self.local_ip.split('/')[0]
            self.global_ip = self.global_ip.split('/')[0]

        main_thread = threading.Thread(target=self.main_loop)
        main_thread.start()

        connect_thread = threading.Thread(target=self.connect_to_switch)
        connect_thread.start()

    def stop(self):
        self.running = False

    def open_udp_port(self):
        # Open a listening socket on UDP
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(self.local_ip)
        self.udp_sock.bind((LOCAL_HOST, 0))
        self.udp_port = self.udp_sock.getsockname()[1]
        print(f"Local switch UDP port: {self.udp_port}")

    def open_tcp_port(self):
        # Open a listening port on TCP
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.bind((LOCAL_HOST, 0))
        self.tcp_port = self.tcp_sock.getsockname()[1]
        self.tcp_sock.listen()
        print(f"Local switch TCP port: {self.tcp_port}")

    def connect_to_switch(self):
        # Create a TCP connection to another global/mixed switch
        while self.running:
            if self.switch_type == 'local' or self.switch_type == 'global':
                try:
                    message = input()
                except:
                    continue
                if message.startswith('connect'):
                    _, connect_port = message.split(' ')
                    connect_port = int(connect_port)
                    new_connection_thread = threading.Thread(target=self.greeting_protocol, args=(connect_port,))
                    new_connection_thread.start()
                    # self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # self.client_sock.connect((LOCAL_HOST, connect_port))
                    # self.greeting_protocol(connect_port)

    # TODO: must have separate loop for TCP and UDP sockets -- global sockets error here because no UDP socket
    def main_loop(self):
        # Main loop to handle incoming packets
        while self.running:
            try:
                conn, addr = self.udp_sock.accept()
                packet = conn.recv(4096)
                self.handle_packet(packet, addr)
            except socket.error:
                pass

            try:
                conn, addr = self.tcp_sock.accept()
                new_connection = Connection('local', conn)
                self.connections.append(new_connection)
                print(f'addr: {addr}')
                self.handle_connection(new_connection)

            except socket.error:
                pass

    def handle_connection(self, connection):
        while self.running:
            try:
                packet = connection.connection.recv(4096)
                self.handle_packet(packet, connection)
            except socket.error:
                pass

    def greeting_protocol(self, connect_port):

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket = Connection('local', client_sock)
        self.connections.append(client_socket)
        client_socket.connection.connect((LOCAL_HOST, connect_port))

        # send discovery
        discovery_packet = self.create_packet(DISCOVERY_01)
        client_socket.connection.send(discovery_packet)

        connection_thread = threading.Thread(target=self.receive_data, args=(client_socket,))
        connection_thread.start()

    def receive_data(self, client_socket):
        while self.running:
            try:
                packet = client_socket.connection.recv(4096)
                self.handle_packet(packet, client_socket)
            except socket.error:
                pass

    def create_packet(self, mode, source_ip='0.0.0.0', dest_ip='0.0.0.0', data='0.0.0.0'):
        packet = bytearray()
        print(f'Create packet:\n  mode: {mode} \n  source_ip: {source_ip}\n  dest_ip: {dest_ip}\n  data: {data}')

        # append source ip
        for elem in socket.inet_aton(source_ip):
            packet.append(elem)

        # append dest ip
        for elem in socket.inet_aton(dest_ip):
            packet.append(elem)

        # append reserve
        for _ in range(3):
            packet.append(RESERVED_BITS)

        # append mode
        packet.append(mode)

        try:
            socket.inet_aton(data)
        except socket.error:
            for char in data:
                packet.append(ord(char))
        else:
            # append assigned address
            for elem in socket.inet_aton(data):
                packet.append(elem)

        self.send_packets.append(packet)
        return packet

    def handle_packet(self, packet, connection):
        # Handle a received packet
        # Extract mode (1 byte)
        print('Check1')
        mode = packet[11]
        print(f'Check mode: {mode}')
        # print out the packet contents
        extract_packet(packet)

        if mode == DISCOVERY_01:
            self.handle_discovery(packet, connection)
        elif mode == OFFER_02:
            self.handle_offer(packet, connection)
        elif mode == REQUEST_03:
            self.handle_request(packet, connection)
        elif mode == ACK_04:
            self.handle_acknowledge(packet, connection)
        elif mode == ASK_06:
            self.handle_ask(packet, connection)
        elif mode == DATA_05:
            self.handle_data(packet, connection)
        elif mode == READY_07:
            self.handle_ready(packet, connection)
        elif mode == LOCATION_08:
            self.handle_location(packet, connection)
        elif mode == FRAGMENT_0A:
            self.handle_fragment(packet, connection)
        elif mode == FRAGMENT_END_0B:
            self.handle_fragment_end(packet, connection)
        else:
            print("Unknown packet type")

    def handle_discovery(self, packet, connection):
        # Handle a Discovery packet
        # print(f"Discovery packet received from {connection.address}. \n Source IP: {socket.inet_ntoa(packet[:4])} "
        #       f"\n Destination IP: {socket.inet_ntoa(packet[4:8])} \n Mode: {packet[11]}")

        # TODO: Assigned IP (data) should be allocated
        offer_packet = self.create_packet(OFFER_02, self.global_ip.split('/')[0], '0.0.0.0', '130.102.72.8')
        print(f'address: {connection.address}')
        connection.connection.send(offer_packet)

    def handle_offer(self, packet, connection):
        # Handle an Offer packet
        # Extract source IP address (4 bytes), use this as destination IP in packet
        source_ip = socket.inet_ntoa(packet[:4])
        # Extract assigned address if it is an IP address (4 bytes)
        data = socket.inet_ntoa(packet[12:16])

        request_packet = self.create_packet(REQUEST_03, '0.0.0.0', source_ip, data)
        connection.connection.send(request_packet)
        # TODO: when receiveing an offer packet, it is now a socket and not a connection (my data type). Fix this.
        print(f"Offer packet received from {connection}")

    def handle_request(self, packet, connection):
        # Handle a Request packet
        source_ip = self.global_ip
        print(f"Request packet received from {connection}")
        # Extract assigned address if it is an IP address (4 bytes), use as data and destination_ip
        data = socket.inet_ntoa(packet[12:16])

        acknowledge_packet = self.create_packet(ACK_04, source_ip, data, data)
        connection.connection.send(acknowledge_packet)

    def handle_acknowledge(self, packet, address):
        # Handle an Acknowledge packet
        print(f"Acknowledge packet received from {address}")

    def handle_data(self, packet, address):
        # Handle a Data packet
        print(f"Data packet received from {address}")

    def handle_query(self, packet, address):
        # Handle a Query packet
        print(f"Query packet received from {address}")

    def handle_ready(self, packet, address):
        # Handle a Ready packet
        print(f"Ready packet received from {address}")

    def handle_location(self, packet, address):
        # Handle a Location packet
        print(f"Location packet received from {address}")

    def handle_distance(self, packet, address):
        # Handle a Distance packet
        print(f"Distance packet received from {address}")

    def handle_more_fragments(self, packet, address):
        # Handle a More Fragments packet
        print(f"More Fragments packet received from {address}")

    def handle_last_fragment(self, packet, address):
        # Handle a Last Fragment packet
        print(f"Last Fragment packet received from {address}")


# Easy test: local
switch = RUSHBSwitch("local", "192.168.0.1/24", "1.1.1.1/24", 50, 20)

# Easy test: mixed
# switch = RUSHBSwitch('local', '192.168.0.1/24', '130.102.72.10/24', 50, 20)

# Easy test: global
# switch = RUSHBSwitch('global', None, '130.102.72.10/24', 50, 20)

switch.start()


## Run from console
# if __name__ == "__main__":
#     if len(sys.argv) < 5:
#         print("Invalid number of arguments.")
#         sys.exit(1)
#
#     switch_type = sys.argv[1]
#     ip_address = sys.argv[2].split('/')[0]
#     latitude = int(sys.argv[3])
#     longitude = int(sys.argv[4])
#     global_ip_address = None
#
#     if switch_type == 'local' and len(sys.argv) == 6:
#         switch_type == 'mixed'
#
#     if switch_type == 'local':
#         if len(sys.argv) != 5:
#             print("Invalid number of arguments.")
#             sys.exit(1)
#     elif switch_type == 'global':
#         if len(sys.argv) != 5:
#             print("Invalid number of arguments.")
#             sys.exit(1)
#         global_ip_address = ip_address
#     elif switch_type == 'mixed':
#         if len(sys.argv) != 6:
#             print("Invalid number of arguments.")
#             sys.exit(1)
#         global_ip_address = sys.argv[3].split('/')[0]
#         latitude = int(sys.argv[4])
#         longitude = int(sys.argv[5])
#     else:
#         print("Invalid switch type.")
#         sys.exit(1)
#
#     switch = RUSHBSwitch(switch_type, ip_address, latitude, longitude, global_ip_address)
#     switch.start()

def extract_packet(packet):
    # Extract source IP address (4 bytes)
    source_ip = socket.inet_ntoa(packet[:4])

    # Extract destination IP address (4 bytes)
    dest_ip = socket.inet_ntoa(packet[4:8])

    # Extract reserved bits (3 bytes)
    reserved_bits = packet[8:11]

    # data = ''.join(chr(byte) for byte in packet[12:])
    data = socket.inet_ntoa(packet[12:16])

    # Extract mode (1 byte)
    mode = packet[11]

    print(f'Received packet:\n  source_ip: {source_ip}\n  dest_ip: {dest_ip}\n  '
          f'reserved_bits: {reserved_bits}\n  mode: {mode}\n  data: {data}')
    # # Check if the data is an IP address or a string
    # try:
    #     # Extract assigned address if it is an IP address (4 bytes)
    #     data = socket.inet_ntoa(packet[12:16])
    # except:
    #     # Extract data as a string
    #     data = ''.join(chr(byte) for byte in packet[12:])

