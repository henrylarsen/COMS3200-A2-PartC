import socket
import sys
import threading
import struct

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
DISTANCE_09 = 0x09
FRAGMENT_0A = 0x0a
FRAGMENT_END_0B = 0x0b


class Connection:
    def __init__(self, type, connection):
        self.type = type
        self.connection = connection
        self.address = LOCAL_HOST
        self.distance = None
        self.ip = None
        # If type is 'adapter' then connection is None


def get_num_connections(cidr):
    return (2**(32-int(cidr))) - 2


class RUSHBSwitch:
    def __init__(self, switch_type, local_ip, global_ip, latitude, longitude):
        self.switch_type = switch_type
        self.latitude = latitude
        self.longitude = longitude
        self.running = False
        self.send_packets = []
        self.recv_packets = []
        self.tcp_sock = None
        self.udp_sock = None
        self.connections = []
        self.adapters = dict()
        self.location = 0

        if self.switch_type == 'mixed':
            self.local_ip = local_ip.split('/')[0]
            self.global_ip = global_ip.split('/')[0]
            self.local_cidr =  local_ip.split('/')[1]
            self.global_cidr = global_ip.split('/')[1]
            self.max_local_connections = get_num_connections(self.local_cidr)
            self.max_global_connections = get_num_connections(self.global_cidr)
            # self.num_connections = 0
            self.num_local_connections = 0
            self.num_global_connections = 0
        if self.switch_type == 'local':
            self.ip = local_ip.split('/')[0]
            self.cidr = local_ip.split('/')[1]
            self.max_connections = get_num_connections(self.cidr)
            self.num_connections = 0
        if self.switch_type == 'global':
            self.ip = global_ip.split('/')[0]
            self.cidr = global_ip.split('/')[1]
            self.max_connections = get_num_connections(self.cidr)
            self.num_connections = 0

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
        # if self.switch_type == 'local':
        #     self.ip = self.ip.split('/')[0]
        # elif self.switch_type == 'global':
        #     self.ip = self.ip.split('/')[0]
        # elif self.switch_type == 'mixed':
        #     self.local_ip = self.local_ip.split('/')[0]
        #     self.global_ip = self.global_ip.split('/')[0]

        if self.switch_type == 'local' or self.switch_type == 'mixed':
            udp_thread = threading.Thread(target=self.udp_listener)
            udp_thread.start()

        tcp_thread = threading.Thread(target=self.tcp_listener)
        tcp_thread.start()

        connect_thread = threading.Thread(target=self.connect_to_switch)
        connect_thread.start()

    def stop(self):
        self.running = False

    def open_udp_port(self):
        # Open a listening socket on UDP
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind((LOCAL_HOST, 0))
        self.udp_port = self.udp_sock.getsockname()[1]
        # print(f"Local switch UDP port: {self.udp_port}")
        print(self.udp_port)

    def open_tcp_port(self):
        # Open a listening port on TCP
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.bind((LOCAL_HOST, 0))
        self.tcp_port = self.tcp_sock.getsockname()[1]
        self.tcp_sock.listen()
        # print(f"Local switch TCP port: {self.tcp_port}")
        print(self.tcp_port)

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
    def udp_listener(self):
        # Main loop to handle incoming packets
        while self.running:
            try:
                packet, addr = self.udp_sock.recvfrom(PACKET_SIZE)
                if addr not in self.adapters:
                    new_connection = Connection('adapter', addr)
                    self.connections.append(new_connection)
                    self.adapters[addr] = new_connection
                    if self.switch_type == 'mixed':
                        self.num_local_connections = self.num_local_connections + 1
                    else:
                        self.num_connections = self.num_connections + 1
                    self.handle_packet(packet, new_connection)
                else:
                    self.handle_packet(packet, self.adapters[addr])
            #
            # except Exception as e:
            #     print(f"Exception occurred: {e}")

            except socket.error:
                pass

    def tcp_listener(self):
        try:
            conn, addr = self.tcp_sock.accept()
            new_connection = Connection('local', conn)
            self.connections.append(new_connection)
            if self.switch_type == 'mixed':
                self.num_global_connections = self.num_global_connections + 1
            else:
                self.num_connections = self.num_connections + 1
            connection_thread = threading.Thread(target=self.handle_connection, args=(new_connection,))
            connection_thread.start()

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

        if isinstance(data, str):
            try:
                socket.inet_aton(data)
                # print(f'data1: {data}')
            except socket.error:
                for char in data:
                    packet.append(ord(char))
            else:
                # append assigned address
                for elem in socket.inet_aton(data):
                    packet.append(elem)

        elif isinstance(data, bytearray):
            for byte in data:
                packet.append(byte)

        self.send_packets.append(packet)
        return packet

    def handle_packet(self, packet, connection):
        # Handle a received packet
        # Extract mode (1 byte)
        print(f'packet: {packet}')
        mode = packet[11]
        # print(f'Check mode: {mode}')
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
        elif mode == DISTANCE_09:
            self.handle_distance(packet, connection)
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
        source_ip = self.global_ip if self.switch_type == 'mixed' else self.ip

        # TODO: add implementation for mixed switches
        if self.switch_type == 'mixed':
            if self.num_global_connections == self.max_global_connections or \
                    self.num_local_connections == self.max_local_connections:
                return
        elif self.num_connections == self.max_connections:
            return

        if self.switch_type == "mixed":
            if connection.type == "local" or "adapter":
                offer_ip = self.get_next_ip(self.local_ip, 'local')
            else:
                offer_ip = self.get_next_ip(self.global_ip, 'global')
        else:
            offer_ip = self.get_next_ip(self.ip)
        connection.ip = offer_ip
        offer_packet = self.create_packet(OFFER_02, source_ip, '0.0.0.0', offer_ip)

        if connection.type == 'adapter':
            self.udp_sock.sendto(offer_packet, connection.connection)
            print('udp sent')
        else:
            connection.connection.send(offer_packet)
            print('tcp sent')

    def get_next_ip(self, ip, s_type=None):
        ip_parts = ip.split('.')
        # TODO: If host IP ends with 10, will this work? the last byte will exceed 255, won't loop back to .1
        if s_type is None:
            ip_parts[-1] = str(int(ip_parts[-1]) + self.num_connections)
        else:
            if s_type == 'global':
                ip_parts[-1] = str(int(ip_parts[-1]) + self.num_global_connections)
            elif s_type == 'local':
                ip_parts[-1] = str(int(ip_parts[-1]) + self.num_local_connections)

        return '.'.join(ip_parts)

    def handle_offer(self, packet, connection):
        # Handle an Offer packet
        # Extract source IP address (4 bytes), use this as destination IP in packet
        source_ip = socket.inet_ntoa(packet[:4])
        # Extract assigned address if it is an IP address (4 bytes)
        data = socket.inet_ntoa(packet[12:16])
        connection.ip = data

        request_packet = self.create_packet(REQUEST_03, '0.0.0.0', source_ip, data)
        connection.connection.send(request_packet)
        # print(f"Offer packet received from {connection}")

    def handle_request(self, packet, connection):
        # Handle a Request packet
        source_ip = self.global_ip if self.switch_type == 'mixed' else self.ip
        # print(f"Request packet received from {connection}")
        # Extract assigned address if it is an IP address (4 bytes), use as data and destination_ip
        data = socket.inet_ntoa(packet[12:16])

        acknowledge_packet = self.create_packet(ACK_04, source_ip, data, data)

        if connection.type == 'adapter':
            self.udp_sock.sendto(acknowledge_packet, connection.connection)
            print('udp sent')
        else:
            connection.connection.send(acknowledge_packet)
            print('tcp sent')

    def handle_acknowledge(self, packet, connection):
        # Handle an Acknowledge packet
        source_ip = socket.inet_ntoa(packet[12:16])
        destination_ip = socket.inet_ntoa(packet[:4])

        data = bytearray()
        latitude_bytes = self.latitude.to_bytes(2, 'big')
        for byte in latitude_bytes:
            data.append(byte)
        longitude_bytes = self.longitude.to_bytes(2, 'big')
        for byte in longitude_bytes:
            data.append(byte)

        location_packet = self.create_packet(LOCATION_08, source_ip, destination_ip, data)
        connection.connection.send(location_packet)
        print(f"Acknowledge packet received from {connection.connection}")
        self.location = 1

    def handle_data(self, packet, address):
        # Handle a Data packet
        print(f"Data packet received from {address}")

    def handle_query(self, packet, address):
        # Handle a Query packet
        print(f"Query packet received from {address}")

    def handle_ready(self, packet, address):
        # Handle a Ready packet
        print(f"Ready packet received from {address}")

    def handle_location(self, packet, connection):
        # Handle a Location packet
        # Send all connecting package but connection the length
        sent_latitude = int.from_bytes(packet[12:14], byteorder='big')
        sent_longitude = int.from_bytes(packet[14:16], byteorder='big')
        distance = self.calculate_euclidean_distance(sent_latitude, sent_longitude)
        connection.distance = distance
        for conn in self.connections:
            if conn == connection:
                pass
            else:
                source_ip = socket.inet_ntoa(packet[4:8])
                destination_ip = connection.ip
                assigned_ip = packet[:4]
                total_distance = (distance + conn.distance).to_bytes(4, 'big')
                data = bytearray()
                for elem in assigned_ip:
                    data.append(elem)
                for byte in total_distance:
                    data.append(byte)
                distance_packet = self.create_packet(DISTANCE_09, source_ip, destination_ip, data)
                conn.connection.send(distance_packet)

        # Send the response location packet if haven't already
        if self.location == 1:
            self.location = 0
            return

        self.location = 1
        source_ip = socket.inet_ntoa(packet[4:8])
        destination_ip = socket.inet_ntoa(packet[:4])

        data = bytearray()
        latitude_bytes = self.latitude.to_bytes(2, 'big')
        for byte in latitude_bytes:
            print(byte)
            data.append(byte)
        longitude_bytes = self.longitude.to_bytes(2, 'big')
        # print(list(longitude_bytes))
        for byte in longitude_bytes:
            print(byte)
            data.append(byte)

        print(f'data: {data}')
        location_packet = self.create_packet(LOCATION_08, source_ip, destination_ip, data)
        connection.connection.send(location_packet)

        print(f"Location packet received from {connection.connection}")

    def handle_distance(self, packet, connection):
        # Handle a Distance packet
        print(f"Distance packet received from {connection}")

    def handle_more_fragments(self, packet, address):
        # Handle a More Fragments packet
        print(f"More Fragments packet received from {address}")

    def handle_last_fragment(self, packet, address):
        # Handle a Last Fragment packet
        print(f"Last Fragment packet received from {address}")

    def calculate_euclidean_distance(self, sent_latitude, sent_longitude):
        return int(((self.latitude - sent_latitude)**2 + (self.longitude - sent_longitude)**2) ** (1/2))


# Easy test: local
# switch = RUSHBSwitch("local", "192.168.1.1/24", None, 1234, 4567)

# Easy test: mixed
# switch = RUSHBSwitch('mixed', '192.168.0.1/24', '130.102.72.10/24', 50, 20)

# Easy test: global
# switch = RUSHBSwitch('global', None, '130.102.72.10/24', 50, 20)

# switch.start()


# TODO: change how mixed is formatted when run from console
# Run from console (to spec)
# if __name__ == "__main__":
#     if len(sys.argv) < 5:
#         print("Invalid number of arguments.")
#         sys.exit(1)
#
#     switch_type = sys.argv[1]
#     ip_address = sys.argv[2]
#     latitude = int(sys.argv[3])
#     longitude = int(sys.argv[4])
#     local_ip_address = None
#     global_ip_address = None
#
#     if switch_type == 'local' and len(sys.argv) == 6:
#         switch_type = 'mixed'
#
#     if switch_type == 'local':
#         if len(sys.argv) != 5:
#             print("Invalid number of arguments.")
#             sys.exit(1)
#         local_ip_address = ip_address
#     elif switch_type == 'global':
#         if len(sys.argv) != 5:
#             print("Invalid number of arguments.")
#             sys.exit(1)
#         global_ip_address = ip_address
#     elif switch_type == 'mixed':
#         if len(sys.argv) != 6:
#             print("Invalid number of arguments.")
#             sys.exit(1)
#         local_ip_address = ip_address
#         global_ip_address = sys.argv[5]
#
#     else:
#         print("Invalid switch type.")
#         sys.exit(1)
#
#     switch = RUSHBSwitch(switch_type, local_ip_address, global_ip_address, latitude, longitude)
#     switch.start()

# Run from console (to tests)
if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Invalid number of arguments.")
        sys.exit(1)

    if len(sys.argv) == 6:
        switch_type = "mixed"
        local_ip_address = sys.argv[2]
        global_ip_address = sys.argv[3]
        latitude = int(sys.argv[4])
        longitude = int(sys.argv[5])

    elif len(sys.argv) == 5:
        switch_type = sys.argv[1]
        if switch_type == 'local':
            local_ip_address = sys.argv[2]
            global_ip_address = None
        elif switch_type == 'global':
            global_ip_address = sys.argv[2]
            local_ip_address = None
        else:
            print("Invalid switch type.")
            sys.exit(1)
        latitude = int(sys.argv[3])
        longitude = int(sys.argv[4])

    else:
        print("Invalid number of arguments.")
        sys.exit(1)

    switch = RUSHBSwitch(switch_type, local_ip_address, global_ip_address, latitude, longitude)
    switch.start()


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

    #     # Extract data as a string
    #     data = ''.join(chr(byte) for byte in packet[12:])
