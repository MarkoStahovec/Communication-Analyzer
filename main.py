# Marko Stahovec
# PKS - 1.zadanie
import codecs
import os.path

from scapy.all import *
from binascii import hexlify

"""
import dpkt

file = open('vz/eth-1.pcap', 'rb')
pcap = dpkt.pcap.Reader(file)
packets = pcap.readpkts()
packets = packets[0:5]


print(packets)
print(type(packets[0]))
"""


# frame_id = 1

# this function opens a pcap file and returns it in a readable format
def open_file():
    while 1:
        filen = input('Názov súboru (napr. \'eth-2\'): ')
        if filen == "q":
            exit(1)
        filen = "vz/" + filen + ".pcap"
        if os.path.isfile(filen):
            return rdpcap(filen)
        else:
            continue


# prints out data (payload) of a frame
def print_hex(data_s):
    for i in range(1, len(data_s) + 1):
        print(data_s[i - 1].upper(), end='')
        if i % 32 == 0:  # conditions for correct wireshark spacing
            print()
        elif i % 16 == 0:
            print('  ', end='')
        elif i % 2 == 0:
            print(' ', end='')
    print()
    print()


# prints out MAC address in a correct format
def print_mac_format(data_):
    for i in range(1, len(data_) + 1):
        print(data_[i - 1].upper(), end='')
        if i % 2 == 0:
            print(' ', end='')
    print()


# prints out an ipv4 address in a correct format
def print_v4_format(data_):
    output_ipv4 = ""
    arr = []
    for i in range(0, 4):  # each cycle takes care of one octet
        arr.append(data_[2 * i] + data_[2 * i + 1])  # takes two numbers as two numbers make up one octet
        byte = int(arr[i], 16)  # converts them into decimal format
        output_ipv4 = output_ipv4 + str(byte) + "."  # adds dot after an octet

    output_ipv4 = output_ipv4[:-1]  # deletes last dot in the format
    print(output_ipv4)


# extracts information from a header in given interval
def get_header_information(frame, start, end):
    return frame[start:(end + 1)]


# prints out the length of a given frame
def print_frame_length(frame):
    frame_length = len(frame) / 2

    # frame lenghts
    print(f"Dĺžka rámca poskytnutá pcap API - {int(frame_length)} B")
    if frame_length + 4 > 64:
        print(f"Dĺžka rámca prenášaného po médiu - {int(frame_length + 4)} B")
    else:
        print(f"Dĺžka rámca prenášaného po médiu - 64 B")


# prints both mac addresses from a given frame
def print_mac_address(frame):
    print(f"Zdrojová MAC adresa: ", end='')
    print_mac_format(get_header_information(frame, 12, 23))
    print(f"Cieľová MAC adresa: ", end='')
    print_mac_format(get_header_information(frame, 0, 11))


# loads data from a file into a given dictionary
def load_data(frame, database, dict_):
    with open(database) as f:
        for line in f:
            parts = line.rstrip("\n").split(' ', 1)  # strips \n from the end of a line and leaves strings as a whole
            key = parts.pop(0)
            dict_[key] = parts

    return dict_

# this function isolates tftp frames to correctly identify tftp streams in order to complete print ports
def isolate_tftp_frames(data, tftp):
    tftp_database = []
    tftp_all = []
    for i in range(0, len(data)):  # goes through all the frames and adds them into their respective connections
        frame = bytes(data[i])
        frame = codecs.decode(hexlify(frame))

        # filter only udp frames
        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46, 47) == "11":
            add_frame_to_connection(tftp_database, i + 1, get_header_information(frame, 52, 59),
                                    get_header_information(frame, 60, 67),
                                    get_header_information(move_to_transport_protocol(frame), 0, 3),
                                    get_header_information(move_to_transport_protocol(frame), 4, 7), frame)

    for i in range(0, len(tftp_database)):  # adds the first frames into its connection
        if i >= len(tftp_database) - 1:
            break
        stream = tftp_database[i]
        if (get_header_information(move_to_transport_protocol(stream["Frame"][0]), 0, 3) == "0045" or
            get_header_information(move_to_transport_protocol(stream["Frame"][0]), 4, 7) == "0045") and \
                len(stream["FID"]) == 1:
            tftp_database[i + 1]["FID"].insert(0, stream["FID"][0])
            tftp_database[i + 1]["ip_src"].insert(0, stream["ip_src"][0])
            tftp_database[i + 1]["ip_dest"].insert(0, stream["ip_dest"][0])
            tftp_database[i + 1]["port_src"].insert(0, stream["port_src"][0])
            tftp_database[i + 1]["port_dest"].insert(0, stream["port_dest"][0])
            tftp_database[i + 1]["Frame"].insert(0, stream["Frame"][0])

            del tftp_database[i]

    # add all tftp frames into one list
    for stream in tftp_database:
        if get_header_information(move_to_transport_protocol(stream["Frame"][0]), 0, 3) == "0045" or \
                get_header_information(move_to_transport_protocol(stream["Frame"][0]), 4, 7) == "0045":
            for i in range(0, len(stream["FID"])):
                tftp_all.append(stream["FID"][i])

    return tftp_all


# prints out the type of a frame
def print_frame_type(frame):
    if int(get_header_information(frame, 24, 27), 16) >= 1536:
        print("Ethernet II")
    elif get_header_information(frame, 28, 31) == "aaaa":
        print("IEEE 802.3 LLC + SNAP")
    elif get_header_information(frame, 28, 31) == "ffff":
        print("IEEE 802.3 RAW")
    else:
        print("IEEE 802.3 LLC")
    return


# retrieves a value from dictionary and returns it as a string
def retrieve_string_from_dict(dict_, value):
    listvalue = dict_.get(value)
    if listvalue is None:
        print("Neznámy protokol")
    else:
        stringvalue = ''.join(listvalue)
        return stringvalue


# prints both ip addresses from a given frame
def print_ipv4_addresses(src, dest):
    print("Zdrojová IP adresa: ", end='')
    print_v4_format(src)
    print("Cieľová IP adresa: ", end='')
    print_v4_format(dest)
    return


# prints out statistics for a given file regarding ip addresses and the address that sent out most packets
def print_ipv4_stats(ipv4_database):
    most_frequent_address = ""
    count_frequent_address = 0

    print("IP adresy vysielajúcich uzlov:")

    for address in ipv4_database:  # cycles through all ip addresses in a file
        if ipv4_database[address] > count_frequent_address:  # swap values if we found an address with more packets sent
            most_frequent_address = address
            count_frequent_address = ipv4_database[address]
        print_v4_format(address)  # print out the address

    print(f"\nAdresa uzla s najväčším počtom odoslaných paketov:")
    print_v4_format(most_frequent_address)
    print(f"{count_frequent_address} paketov")


# returns a pointer to the start of a transport protocol calculating from IHL (ip header length)
def move_to_transport_protocol(frame):
    return frame[(14 + (int(get_header_information(frame, 29, 29), 16) * 4)) * 2:len(frame)]


# prints out ports accordingly to tcp/udp protocols
def print_ports(ports, frame, fid, ipprotocol_value, tftp_database):
    if ipprotocol_value == "06":  # condition to load either tcp ports or udp ports
        load_data(frame, "tcpports.txt", ports)
    elif ipprotocol_value == "11":
        load_data(frame, "udpports.txt", ports)

    # condition for transport protocol name
    if get_header_information(move_to_transport_protocol(frame), 0, 3) in ports:
        print(retrieve_string_from_dict(ports, get_header_information(move_to_transport_protocol(frame), 0, 3)))
    elif get_header_information(move_to_transport_protocol(frame), 4, 7) in ports:
        print(retrieve_string_from_dict(ports, get_header_information(move_to_transport_protocol(frame), 4, 7)))
    elif tftp_database is not None and fid in tftp_database:
        print("TFTP")
    else:
        print("Neznámy port")

    if ipprotocol_value == "06" or ipprotocol_value == "11":  # condition for printing ports' numbers
        print("Zdrojový port: ", int(get_header_information(move_to_transport_protocol(frame), 0, 3), 16))
        print("Cieľový port: ", int(get_header_information(move_to_transport_protocol(frame), 4, 7), 16))


# prints a protocol and additional information for specific protocol
def print_protocol(frame, fid, tftp_database):
    ethertypes = {}
    ipprotocols = {}
    ports = {}
    lsapvalues = {}

    load_data(frame, "ethertypes.txt", ethertypes)

    ethertype_value = get_header_information(frame, 24, 27)
    sap_value = get_header_information(frame, 28, 31)

    if int(get_header_information(frame, 24, 27), 16) >= 1536:  # when ethertype is ethertype, not length

        if ethertype_value in ethertypes:
            print(retrieve_string_from_dict(ethertypes, ethertype_value))
        else:
            print("Neznámy ethertype.")

        if ethertype_value == "0800":  # if ethertype is ipv4
            print_ipv4_addresses(get_header_information(frame, 52, 59), get_header_information(frame, 60, 67))

            load_data(frame, "ipprotocols.txt", ipprotocols)
            ipprotocol_value = get_header_information(frame, 46, 47)
            print(retrieve_string_from_dict(ipprotocols, ipprotocol_value))  # prints an ip protocol

            if ipprotocol_value == "01":  # Condition for ICMP
                icmptypes = {}
                load_data(frame, "icmptypes.txt", icmptypes)
                if get_header_information(move_to_transport_protocol(frame), 0, 1) in icmptypes:
                    print(retrieve_string_from_dict(icmptypes,
                                                    get_header_information(move_to_transport_protocol(frame), 0, 1)))
                else:
                    print("Neznámy ICMP typ")
                return

            print_ports(ports, frame, fid, ipprotocol_value, tftp_database)

        if ethertype_value == "0806":  # if ethertype is arp
            print_ipv4_addresses(get_header_information(frame, 56, 63), get_header_information(frame, 76, 83))
            if get_header_information(frame, 40, 43) == "0001":
                print("ARP Request")
            elif get_header_information(frame, 40, 43) == "0002":
                print("ARP Reply")
            else:
                print("Wrong Operation")

    else:
        if sap_value == "ffff":  # condition for IEEE 802.3 raw iprotocol
            print("IPX")

        elif sap_value == "aaaa":  # condition for IEEE 802.3 LLC + SNAP iprotocol, has ethertype on different place
            ethertype_value = get_header_information(frame, 40, 43)
            if ethertype_value in ethertypes:
                print(retrieve_string_from_dict(ethertypes, ethertype_value))

        else:  # condition for IEEE 802.3 LLC, prints protocol regarding lsap value
            load_data(frame, "lsaps.txt", lsapvalues)
            lsap_value = get_header_information(frame, 28, 29)

            print(retrieve_string_from_dict(lsapvalues, lsap_value))

    return


# prints all the information about the single frame
def print_output(frame, fid, tftp_database):
    print(f"Rámec {fid}")
    print_frame_length(frame)
    print_frame_type(frame)

    print_mac_address(frame)
    print_protocol(frame, fid, tftp_database)
    print_hex(frame)


# returns a list of indices that need to be ignored when printing more than 20 frame in a communication
def check_frame_overflow(data, counter, ignore_indices, protocol):
    for i in range(0, len(data)):
        frame = bytes(data[i])
        frame = codecs.decode(hexlify(frame))

        # counts all the frames corresponding to particular protocol
        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46, 47) == protocol:
            counter += 1

    threshold = counter - 10
    if counter > 20:  # if there are more than 20 frames in a comm.
        while threshold > 10:
            ignore_indices.append(threshold)  # ignore these indices
            threshold -= 1

    return counter, threshold


# adds an ipv4 frame to a connection stream or creates a new stream if there are no matching streams already
def add_frame_to_connection(conn_stream, fid, src_ip, dest_ip, src_port, dest_port, frame):
    frame_dict = {"FID": [fid], "ip_src": [src_ip], "ip_dest": [dest_ip], "port_src": [src_port],
                  "port_dest": [dest_port], "Frame": [frame]}
    for i in range(0, len(conn_stream)):  # checks for already existing streams
        if (conn_stream[i]["ip_src"][0] == src_ip) and (conn_stream[i]["ip_dest"][0] == dest_ip) and \
                (conn_stream[i]["port_src"][0] == src_port) and (conn_stream[i]["port_dest"][0] == dest_port):
            conn_stream[i]["FID"].append(fid)
            conn_stream[i]["ip_src"].append(src_ip)
            conn_stream[i]["ip_dest"].append(dest_ip)
            conn_stream[i]["port_src"].append(src_port)
            conn_stream[i]["port_dest"].append(dest_port)
            conn_stream[i]["Frame"].append(frame)
            return

        elif (conn_stream[i]["ip_src"][0] == dest_ip) and (conn_stream[i]["ip_dest"][0] == src_ip) and \
                (conn_stream[i]["port_src"][0] == dest_port) and (conn_stream[i]["port_dest"][0] == src_port):
            conn_stream[i]["FID"].append(fid)
            conn_stream[i]["ip_src"].append(src_ip)
            conn_stream[i]["ip_dest"].append(dest_ip)
            conn_stream[i]["port_src"].append(src_port)
            conn_stream[i]["port_dest"].append(dest_port)
            conn_stream[i]["Frame"].append(frame)
            return

    conn_stream.append(frame_dict)  # if no stream with these parameters exists, create a new one


# adds an arp frame to a connection stream or creates a new stream if there are no matching streams already
def add_arp_to_connection(arp_stream, fid, src_ip, dest_ip, src_mac, dst_mac, frame):
    frame_dict = {"FID": [fid], "ip_src": [src_ip], "ip_dest": [dest_ip],
                  "mac_src": [src_mac], "mac_dst": [dst_mac], "Frame": [frame], "is_open": True}
    for i in range(0, len(arp_stream)):  # checks for already existing streams
        if ((arp_stream[i]["ip_src"][0] == src_ip) and (arp_stream[i]["ip_dest"][0] == dest_ip) and
                (arp_stream[i]["mac_src"][0] == src_mac) and (arp_stream[i]["mac_dst"][0] == dst_mac)
                and arp_stream[i]["is_open"] is True):
            arp_stream[i]["FID"].append(fid)
            arp_stream[i]["ip_src"].append(src_ip)
            arp_stream[i]["ip_dest"].append(dest_ip)
            arp_stream[i]["mac_src"].append(src_mac)
            arp_stream[i]["mac_dst"].append(dst_mac)
            arp_stream[i]["Frame"].append(frame)

            # specific condition for replies, since they automatically close a connection
            if get_header_information(frame, 40, 43) == "0001":
                return
            elif get_header_information(frame, 40, 43) == "0002":
                arp_stream[i]["is_open"] = False
            return

        elif ((arp_stream[i]["ip_src"][0] == dest_ip) and (arp_stream[i]["ip_dest"][0] == src_ip) and
              (arp_stream[i]["mac_src"][0] == dst_mac)
              and arp_stream[i]["is_open"] is True):
            arp_stream[i]["FID"].append(fid)
            arp_stream[i]["ip_src"].append(src_ip)
            arp_stream[i]["ip_dest"].append(dest_ip)
            arp_stream[i]["mac_src"].append(src_mac)
            arp_stream[i]["mac_dst"].append(dst_mac)
            arp_stream[i]["Frame"].append(frame)

            # specific condition for replies, since they automatically close a connection
            if get_header_information(frame, 40, 43) == "0001":
                return
            elif get_header_information(frame, 40, 43) == "0002":
                arp_stream[i]["is_open"] = False
            return

    if get_header_information(frame, 40, 43) == "0002":  # condition for if when there is reply to nonrequest
        frame_dict["is_open"] = False

    arp_stream.append(frame_dict)  # if no stream with these parameters exists, create a new one


# analyzes tcp communication and prints first complete and first incomplete communication
def tcp_communication(data, selector):
    counter = 0  # this is a counter for how many frames are in the communication
    ignore_indices = []  # this is an array of ignored indices in case there are more than 20 frames in a communication
    tcpports = {}
    conn_stream = []  # list of all the communications in a file
    complete = incomplete = False  # boolean selectors for communications
    load_data(data, "tcpports.txt", tcpports)

    for i in range(0, len(data)):  # goes through all the frames and adds them into their respective connections
        frame = bytes(data[i])
        frame = codecs.decode(hexlify(frame))

        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46, 47) == "06":
            if selector in tcpports:
                if get_header_information(move_to_transport_protocol(frame), 0, 3) == selector or \
                        get_header_information(move_to_transport_protocol(frame), 4, 7) == selector:
                    add_frame_to_connection(conn_stream, i + 1, get_header_information(frame, 52, 59),
                                            get_header_information(frame, 60, 67),
                                            get_header_information(move_to_transport_protocol(frame), 0, 3),
                                            get_header_information(move_to_transport_protocol(frame), 4, 7), frame)

    for stream in conn_stream:  # cycles through streams to find complete and incomplete one and prints them out
        if complete and incomplete:  # if streams were found, no need to cycle further
            break
        beg_correct = False  # selector for correct connection opening (SYN on both ends)
        end_correct = False
        last = last1 = last2 = last3 = 0  # pointers to last 4 frames' flags
        if len(stream["FID"]) < 3:
            continue
        else:
            # flags for each frames in a string format
            firstflags = str(
                bin(int(get_header_information(move_to_transport_protocol(stream["Frame"][0]), 25, 27), 16)))[2:].zfill(
                6)
            secondflags = str(
                bin(int(get_header_information(move_to_transport_protocol(stream["Frame"][1]), 25, 27), 16)))[2:].zfill(
                6)
            thirdflags = str(
                bin(int(get_header_information(move_to_transport_protocol(stream["Frame"][2]), 25, 27), 16)))[2:].zfill(
                6)

            # condition for correct connection opening
            if firstflags[-2] == "1" and (secondflags[-2] == "1" and secondflags[-5] == "1") and thirdflags[-5] == "1":
                if stream["ip_src"][0] == stream["ip_dest"][1] and \
                        stream["ip_dest"][0] == stream["ip_src"][1] and \
                        stream["port_src"][0] == stream["port_dest"][1] and \
                        stream["port_dest"][0] == stream["port_src"][1]:
                    beg_correct = True

            lastflags = str(
                bin(int(get_header_information(move_to_transport_protocol(stream["Frame"][-1]), 25, 27), 16)))[
                        2:].zfill(6)
            last1flags = str(
                bin(int(get_header_information(move_to_transport_protocol(stream["Frame"][-2]), 25, 27), 16)))[
                         2:].zfill(6)

            if len(stream["FID"]) > 3:
                last2flags = str(
                    bin(int(get_header_information(move_to_transport_protocol(stream["Frame"][-3]), 25, 27), 16)))[
                             2:].zfill(6)
                last3flags = str(
                    bin(int(get_header_information(move_to_transport_protocol(stream["Frame"][-4]), 25, 27), 16)))[
                             2:].zfill(6)

                # all conditions for different scenarios when closing a tcp connection
                if (last3flags[-1] == "1" and last3flags[-5] == "1") and last2flags[-5] == "1" and (
                        last1flags[-1] == "1" and last1flags[-5] == "1") \
                        and lastflags[-5] == "1":
                    if (stream["ip_src"][len(stream["FID"]) - 4] == stream["ip_src"][len(stream["FID"]) - 1]) and \
                            (stream["ip_src"][len(stream["FID"]) - 3] == stream["ip_src"][len(stream["FID"]) - 2]):
                        end_correct = True

                elif (last3flags[-1] == "1" and last3flags[-5] == "1") and \
                        (last2flags[-1] == "1" and last2flags[-5] == "1") and last1flags[-5] == "1" \
                        and lastflags[-5] == "1":
                    if (stream["ip_src"][len(stream["FID"]) - 4] == stream["ip_src"][len(stream["FID"]) - 2]) and \
                            (stream["ip_src"][len(stream["FID"]) - 3] == stream["ip_src"][len(stream["FID"]) - 1]):
                        end_correct = True

                elif (last2flags[-1] == "1" and last2flags[-5] == "1") and \
                        (last1flags[-5] == "1" and last1flags[-1] == "1") \
                        and lastflags[-5] == "1":
                    if stream["ip_src"][len(stream["FID"]) - 3] == stream["ip_src"][len(stream["FID"]) - 1]:
                        end_correct = True

                # rst flag
                elif last1flags[-3] == "1" or lastflags[-3] == "1":
                    end_correct = True

            """
            first = get_header_information(move_to_transport_protocol(stream["Frame"][0]), 25, 27)
            second = get_header_information(move_to_transport_protocol(stream["Frame"][1]), 25, 27)
            third = get_header_information(move_to_transport_protocol(stream["Frame"][2]), 25, 27)
            # check if connection is opened correctly
            if first == "002" and second == "012" and third == "010":
                if stream["ip_src"][0] == stream["ip_dest"][1] and \
                        stream["ip_dest"][0] == stream["ip_src"][1] and \
                        stream["port_src"][0] == stream["port_dest"][1] and \
                        stream["port_dest"][0] == stream["port_src"][1]:
                    beg_correct = True
            if len(stream["FID"]) > 3:
                fourth = get_header_information(move_to_transport_protocol(stream["Frame"][3]), 25, 27)
                if first == "002" and second == "010" and third == "012" and fourth == "010":
                    if stream["ip_src"][0] == stream["ip_dest"][2] and \
                            stream["ip_dest"][0] == stream["ip_src"][2] and \
                            stream["port_src"][0] == stream["port_dest"][2] and \
                            stream["port_dest"][0] == stream["port_src"][2]:
                        beg_correct = True

            last = get_header_information(move_to_transport_protocol(stream["Frame"][len(stream["FID"]) - 1]), 25, 27)
            last1 = get_header_information(move_to_transport_protocol(stream["Frame"][len(stream["FID"]) - 2]), 25, 27)

            if len(stream["FID"]) > 3:
                last2 = get_header_information(move_to_transport_protocol(stream["Frame"][len(stream["FID"]) - 3]), 25,
                                               27)
                last3 = get_header_information(move_to_transport_protocol(stream["Frame"][len(stream["FID"]) - 4]), 25,
                                               27)

            # checks if connection is opened correctly
            if (last3 == "019" or last3 == "011" or last3 == "001") and \
                    (last2 == "010") and \
                    (last1 == "019" or last1 == "011" or last1 == "001") and \
                    (last == "010"):
                if (stream["ip_src"][len(stream["FID"]) - 4] == stream["ip_src"][len(stream["FID"]) - 1]) and \
                        (stream["ip_src"][len(stream["FID"]) - 3] == stream["ip_src"][len(stream["FID"]) - 2]):
                    end_correct = True

            elif (last3 == "019" or last3 == "011" or last3 == "001") and \
                    (last2 == "019" or last2 == "011" or last2 == "001") and \
                    (last1 == "010") and (last == "010"):
                if (stream["ip_src"][len(stream["FID"]) - 4] == stream["ip_src"][len(stream["FID"]) - 2]) and \
                        (stream["ip_src"][len(stream["FID"]) - 3] == stream["ip_src"][len(stream["FID"]) - 1]):
                    end_correct = True

            elif (last2 == "019" or last2 == "011" or last2 == "001") and \
                    (last1 == "019" or last1 == "011" or last1 == "001") and last == "010":
                if stream["ip_src"][len(stream["FID"]) - 3] == stream["ip_src"][len(stream["FID"]) - 1]:
                    end_correct = True

            elif last == "004" or last == "014" or last1 == "004" or last1 == "014":
                end_correct = True
            """

            if not complete:
                if beg_correct and end_correct:
                    print("************************************************************************")
                    print("Kompletná komunikácia aj s ukončením")
                    print("************************************************************************")

                    counter = len(stream["Frame"])
                    threshold = counter - 10
                    if counter > 20:  # sets up correct ignored frames for long connections
                        while threshold > 10:
                            ignore_indices.append(threshold)
                            threshold -= 1

                    for i in range(0, len(stream["Frame"])):
                        frame = stream["Frame"][i]

                        # condition whether the frame has an ipv4 protocol and tcp protocol
                        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46,
                                                                                                      47) == "06":
                            if counter in ignore_indices:
                                counter -= 1
                                continue
                            print_output(frame, stream["FID"][i], None)
                            counter -= 1
                    complete = True

            if not incomplete:
                if beg_correct and not end_correct:
                    print("************************************************************************")
                    print("Nekompletná komunikácia bez ukončenia")
                    print("************************************************************************")

                    counter = len(stream["Frame"])
                    threshold = counter - 10
                    if counter > 20:  # sets up correct ignored frames for long connections
                        while threshold > 10:
                            ignore_indices.append(threshold)
                            threshold -= 1

                    for i in range(0, len(stream["Frame"])):
                        frame = stream["Frame"][i]

                        # condition whether the frame has an ipv4 protocol and tcp protocol
                        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46,
                                                                                                      47) == "06":
                            if counter in ignore_indices:
                                counter -= 1
                                continue
                            print_output(frame, stream["FID"][i], None)
                            counter -= 1
                    incomplete = True

    return


# adds an icmp frame to a connection stream or creates a new stream if there are no matching streams already
def add_icmp_to_communication(icmp_stream, fid, src_ip, dest_ip, src_mac, dst_mac, frame):
    frame_dict = {"FID": [fid], "ip_src": [src_ip], "ip_dest": [dest_ip], "mac_src": [src_mac],
                  "mac_dst": [dst_mac], "Frame": [frame], "is_open": True}
    for i in range(0, len(icmp_stream)):  # checks for already existing streams

        """
        if get_header_information(move_to_transport_protocol(frame), 0, 1) != "00" and \
            get_header_information(move_to_transport_protocol(frame), 0, 1) != "08":
            break
        """
        if (icmp_stream[i]["ip_src"][0] == src_ip) and (icmp_stream[i]["ip_dest"][0] == dest_ip) and \
                (icmp_stream[i]["mac_src"][0] == src_mac) and (icmp_stream[i]["mac_dst"][0] == dst_mac) and \
                (icmp_stream[i]["is_open"] is True):

            icmp_stream[i]["FID"].append(fid)
            icmp_stream[i]["ip_src"].append(src_ip)
            icmp_stream[i]["ip_dest"].append(dest_ip)
            icmp_stream[i]["mac_src"].append(src_mac)
            icmp_stream[i]["mac_dst"].append(dst_mac)
            icmp_stream[i]["Frame"].append(frame)

            """
            if get_header_information(move_to_transport_protocol(frame), 12, 15) == \
                    get_header_information(move_to_transport_protocol(icmp_stream[i]["Frame"][-1]), 12, 15) and \
                    get_header_information(move_to_transport_protocol(frame), 0, 1) == "00":
                icmp_stream[i]["is_open"] = False
            elif get_header_information(move_to_transport_protocol(frame), 12, 15) == \
                    get_header_information(move_to_transport_protocol(icmp_stream[i]["Frame"][-1]), 12, 15) and \
                    get_header_information(move_to_transport_protocol(frame), 0, 1) == "08":
                return
            """
            return

        elif (icmp_stream[i]["ip_src"][0] == dest_ip) and (icmp_stream[i]["ip_dest"][0] == src_ip) and \
                (icmp_stream[i]["mac_src"][0] == dst_mac) and (icmp_stream[i]["mac_dst"][0] == src_mac) and \
                (icmp_stream[i]["is_open"] is True):

            icmp_stream[i]["FID"].append(fid)
            icmp_stream[i]["ip_src"].append(src_ip)
            icmp_stream[i]["ip_dest"].append(dest_ip)
            icmp_stream[i]["mac_src"].append(src_mac)
            icmp_stream[i]["mac_dst"].append(dst_mac)
            icmp_stream[i]["Frame"].append(frame)

            """
            if get_header_information(move_to_transport_protocol(frame), 12, 15) == \
                    get_header_information(move_to_transport_protocol(icmp_stream[i]["Frame"][-1]), 12, 15) and \
                    get_header_information(move_to_transport_protocol(frame), 0, 1) == "00":
                icmp_stream[i]["is_open"] = False
            elif get_header_information(move_to_transport_protocol(frame), 12, 15) == \
                    get_header_information(move_to_transport_protocol(icmp_stream[i]["Frame"][-1]), 12, 15) and \
                    get_header_information(move_to_transport_protocol(frame), 0, 1) == "08":
                return
            """
            return

    icmp_stream.append(frame_dict)  # if no stream with these parameters exists, create a new one


# analyzes icmp communication and prints out frames using icmprotocol
def icmp_communication(data):
    counter = 0
    connection_number = 1
    ignore_indices = []
    icmptypes = {}
    icmp_stream = []
    load_data(data, "icmptypes.txt", icmptypes)

    """
    counter, threshold = check_frame_overflow(data, counter, ignore_indices, "01")

    for i in range(0, len(data)):
        frame = bytes(data[i])
        frame = codecs.decode(hexlify(frame))

        # condition whether the frame has an ipv4 protocol and icmp protocol
        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46, 47) == "01":
            if counter in ignore_indices:
                counter -= 1
                continue
            print(f"Rámec {i + 1}")
            print_frame_length(frame)
            print_frame_type(frame)
            print_mac_address(frame)
            print_protocol(frame)

            # condition for type of icmp message to be printed
            if get_header_information(move_to_transport_protocol(frame), 0, 1) in icmptypes:
                print(retrieve_string_from_dict(icmptypes,
                                                get_header_information(move_to_transport_protocol(frame), 0, 1)))
            else:
                print("Neznámy ICMP typ")
            print_hex(frame)
            counter -= 1
    """

    for i in range(0, len(data)):  # goes through all the frames and adds them into their respective connections
        frame = bytes(data[i])
        frame = codecs.decode(hexlify(frame))

        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46, 47) == "01":
            add_icmp_to_communication(icmp_stream, i + 1, get_header_information(frame, 52, 59),
                                      get_header_information(frame, 60, 67),
                                      get_header_information(frame, 0, 11),
                                      get_header_information(frame, 12, 23), frame)

    for i in range(0, len(icmp_stream)):  # cycle through streams
        stream = icmp_stream[i]

        counter = len(stream["Frame"])
        threshold = counter - 10
        if counter > 20:  # condition for streams that are longer than 20 frames
            while threshold > 10:
                ignore_indices.append(threshold)
                threshold -= 1

        print("**************************************************************")
        print(f"ICMP Komunikácia č. {connection_number}")
        print("**************************************************************")
        connection_number += 1

        for x in range(0, len(stream["Frame"])):  # print out all frames in a connection
            frame = stream["Frame"][x]

            # condition whether the frame has an ipv4 protocol and udp protocol
            if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46,
                                                                                          47) == "01":
                if counter in ignore_indices:
                    counter -= 1
                    continue
                print(f"Rámec {stream['FID'][x]}")
                print_frame_length(frame)
                print_frame_type(frame)
                print_mac_address(frame)
                print_protocol(frame, stream['FID'][x], None)

                """
                # condition for type of icmp message to be printed
                if get_header_information(move_to_transport_protocol(frame), 0, 1) in icmptypes:
                    print(retrieve_string_from_dict(icmptypes,
                                                    get_header_information(move_to_transport_protocol(frame), 0,
                                                                           1)))
                else:
                    print("Neznámy ICMP typ")
                """
                print_hex(frame)
                counter -= 1

    return


# analyzes udp communication and prints frames that belong to a specific communication
def udp_communication(data, selector):
    udpports = {}
    load_data(data, "udpports.txt", udpports)

    tftp_database = []
    tftp_database = isolate_tftp_frames(data, tftp_database)

    counter = 0
    connection_number = 1
    ignore_indices = []
    conn_stream = []

    for i in range(0, len(data)):  # goes through all the frames and adds them into their respective connections
        frame = bytes(data[i])
        frame = codecs.decode(hexlify(frame))

        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46, 47) == "11":
            add_frame_to_connection(conn_stream, i + 1, get_header_information(frame, 52, 59),
                                    get_header_information(frame, 60, 67),
                                    get_header_information(move_to_transport_protocol(frame), 0, 3),
                                    get_header_information(move_to_transport_protocol(frame), 4, 7), frame)

    for i in range(0, len(conn_stream)):  # adds the first frames into its connection
        if i >= len(conn_stream) - 1:
            break
        stream = conn_stream[i]
        if (get_header_information(move_to_transport_protocol(stream["Frame"][0]), 0, 3) == "0045" or
            get_header_information(move_to_transport_protocol(stream["Frame"][0]), 4, 7) == "0045") and \
                len(stream["FID"]) == 1:
            conn_stream[i + 1]["FID"].insert(0, stream["FID"][0])
            conn_stream[i + 1]["ip_src"].insert(0, stream["ip_src"][0])
            conn_stream[i + 1]["ip_dest"].insert(0, stream["ip_dest"][0])
            conn_stream[i + 1]["port_src"].insert(0, stream["port_src"][0])
            conn_stream[i + 1]["port_dest"].insert(0, stream["port_dest"][0])
            conn_stream[i + 1]["Frame"].insert(0, stream["Frame"][0])

            del conn_stream[i]

    for i in range(0, len(conn_stream)):  # cycle through streams
        stream = conn_stream[i]

        counter = len(stream["Frame"])
        threshold = counter - 10
        if counter > 20:
            while threshold > 10:
                ignore_indices.append(threshold)
                threshold -= 1

        # condition for when the first doesnt have a 69 port
        if (get_header_information(move_to_transport_protocol(stream["Frame"][0]), 0, 3) != "0045" and
                get_header_information(move_to_transport_protocol(stream["Frame"][0]), 4, 7) != "0045"):
            continue

        print("**************************************************************")
        print(f"TFTP Komunikácia č. {connection_number}")
        print("**************************************************************")
        connection_number += 1

        for x in range(0, len(stream["Frame"])):
            frame = stream["Frame"][x]

            # condition whether the frame has an ipv4 protocol and udp protocol
            if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46,
                                                                                          47) == "11":
                if counter in ignore_indices:
                    counter -= 1
                    continue
                print_output(frame, stream["FID"][x], tftp_database)
                counter -= 1

    return


# analyzes arp communication and prints complete and incomplete arp communications
def arp_communication(data):
    counter = 0
    connection_number = 1
    ignore_indices = []
    arp_stream = []

    for i in range(0, len(data)):  # goes through all the frames and adds them into their respective connections
        frame = bytes(data[i])
        frame = codecs.decode(hexlify(frame))

        if get_header_information(frame, 24, 27) == "0806":
            # print_ipv4_addresses(get_header_information(frame, 56, 63), get_header_information(frame, 76, 83))
            add_arp_to_connection(arp_stream, i + 1, get_header_information(frame, 56, 63),
                                  get_header_information(frame, 76, 83),
                                  get_header_information(frame, 44, 55),
                                  get_header_information(frame, 64, 75), frame)

    for i in range(0, len(arp_stream)):  # prints out all the communication, whether its closed or not
        stream = arp_stream[i]
        if not stream["is_open"] and (stream["ip_src"][0] != stream["ip_dest"][0]):
            print("**************************************************************")
            print(f"ARP Komunikácia č. {connection_number}")
            print("**************************************************************")
            connection_number += 1
            counter = len(stream["Frame"])
            threshold = counter - 10
            if counter > 20:
                while threshold > 10:
                    ignore_indices.append(threshold)
                    threshold -= 1

            for x in range(0, len(stream["Frame"])):
                frame = stream["Frame"][x]

                if get_header_information(frame, 40, 43) == "0001" and x == 0:
                    print("ARP Request, ", end='')
                    print(f"IP Adresa: ", end='')
                    print_v4_format(get_header_information(frame, 56, 63))
                    print("MAC adresa: ???")
                    print(f"Zdrojová IP Adresa: ", end='')
                    print_v4_format(get_header_information(frame, 56, 63))
                    print(f"Cieľová IP Adresa: ", end='')
                    print_v4_format(get_header_information(frame, 76, 83))

                elif get_header_information(frame, 40, 43) == "0002" and x == len(stream["Frame"]) - 1:
                    print("ARP Reply, ", end='')
                    print(f"IP Adresa: ", end='')
                    print_v4_format(get_header_information(frame, 56, 63))
                    print("MAC adresa: ", end='')
                    print_mac_format(get_header_information(frame, 44, 55))
                    print(f"Zdrojová IP Adresa: ", end='')
                    print_v4_format(get_header_information(frame, 56, 63))
                    print(f"Cieľová IP Adresa: ", end='')
                    print_v4_format(get_header_information(frame, 76, 83))

                if get_header_information(frame, 24, 27) == "0806":
                    if counter in ignore_indices:
                        counter -= 1
                        continue
                    print_output(frame, stream["FID"][x], None)
                    counter -= 1

            print("--------------------------------------------------------------")

    connection_number = 1
    for i in range(0, len(arp_stream)):  # prints out all the communication, whether its closed or not
        stream = arp_stream[i]
        if stream["is_open"] or (stream["ip_src"][0] == stream["ip_dest"][0] and len(stream["FID"]) == 1):
            print("**************************************************************")
            print(f"Nekompletná ARP komunikácia {connection_number}")
            print("**************************************************************")
            connection_number += 1
            counter = len(stream["Frame"])
            threshold = counter - 10
            if counter > 20:
                while threshold > 10:
                    ignore_indices.append(threshold)
                    threshold -= 1

            for x in range(0, len(stream["Frame"])):
                frame = stream["Frame"][x]

                if get_header_information(frame, 24, 27) == "0806":
                    if counter in ignore_indices:
                        counter -= 1
                        continue
                    print_output(frame, stream["FID"][x], None)
                    counter -= 1

            print("--------------------------------------------------------------")

    return


# doimplementacna funkcia
def dns_communication(data):
    dns_frame_counter = 0
    udpports = {}
    load_data(data, "udpports.txt", udpports)

    for i in range(0, len(data)):
        frame = bytes(data[i])
        frame = codecs.decode(hexlify(frame))

        if get_header_information(frame, 24, 27) == "0800" and get_header_information(frame, 46, 47) == "11":
            if get_header_information(move_to_transport_protocol(frame), 0, 3) == "0035" or \
                    get_header_information(move_to_transport_protocol(frame), 4, 7) == "0035":
                print_output(frame, i + 1, None)
                dns_frame_counter += 1

    print(f"Počet všetkých DNS rámcov: {dns_frame_counter}")
    return


# main function that calls other functions according to user choice
def start_program(data, selector):
    print(f"-----------------------------------------------------------------------------------------\n"
          f"\t\t\t\t\t\tAnalyzing file {str(data.listname.split('.')[0])}\n"
          f"-----------------------------------------------------------------------------------------\n")
    if selector == "1":
        ipv4_database = {}
        tftp_database = []
        tftp_database = isolate_tftp_frames(data, tftp_database)

        for i in range(0, len(data)):
            frame = bytes(data[i])
            frame = codecs.decode(hexlify(frame))
            # print(codecs.decode(hexlify(frame)))

            if get_header_information(frame, 24,
                                      27) == "0800":  # here we collect all the ethernet II frames for ipv4 stats
                src_address = get_header_information(frame, 52, 59)
                if src_address in ipv4_database:
                    value = ipv4_database[src_address]
                    ipv4_database[src_address] = value + 1
                else:  # if address is not in database, we add it in and its count we set to 1
                    ipv4_database[src_address] = 1

            print_output(frame, i + 1, tftp_database)

        print_ipv4_stats(ipv4_database)

    # this is a condition for tcp protocol family
    elif selector == "2":
        tcp_communication(data, "0050")
    elif selector == "3":
        tcp_communication(data, "01bb")
    elif selector == "4":
        tcp_communication(data, "0017")
    elif selector == "5":
        tcp_communication(data, "0016")
    elif selector == "6":
        tcp_communication(data, "0015")
    elif selector == "7":
        tcp_communication(data, "0014")
    # and more conditions for different protocols to be analyzed
    elif selector == "8":
        udp_communication(data, "0045")

    elif selector == "9":
        icmp_communication(data)

    elif selector == "10":
        arp_communication(data)

    elif selector == "11":
        dns_communication(data)

    else:
        print("Chybný protokol")
        return


# main function
if __name__ == '__main__':
    print("\nAnalyzátor sieťovej komunikácie\nAutor: Marko Stahovec\nZadaj q pre ukončenie programu")
    output = None
    pcapdata = open_file()
    while True:  # while true for endless run
        print("\nZadaj c pre zmenu súboru\n"
              "Zadaj q pre ukončenie programu\nZadaj 1 pre výpis prvých troch úloh\nZadaj 2 pre výpis HTTP\n"
              "Zadaj 3 pre výpis HTTPS\nZadaj 4 pre výpis Telnet\nZadaj 5 pre výpis SSH\n"
              "Zadaj 6 pre výpis FTP riadiacich rámcov\nZadaj 7 pre výpis FTP dátových rámcov\n"
              "Zadaj 8 pre výpis TFTP\nZadaj 9 pre výpis ICMP\nZadaj 10 pre výpis ARP\n"
              "Zadaj 11 pre výpis DNS rámcov (doimplementácia)\n")

        choice = str(input("Výber: "))
        if choice == "q":  # choice for quitting a program
            exit(1)
        elif choice == "c":  # choice for changing an input pcap file
            pcapdata = open_file()
            continue

        outputchoice = input("Výpis do súboru? [a/n]: ")
        # outputfilename = str(pcapdata.listname.split(".")[0])
        # outputfilename = outputfilename + f"-{it}.txt"

        if outputchoice == "a":  # redirect output to a file
            # output = open(outputfilename, "w")
            output = open("output.txt", "a")
            sys.stdout = output

        start_program(pcapdata, choice)  # main runnable function

        if outputchoice == "a":  # redirect output back
            sys.stdout = sys.__stdout__
            output.close()

        print('\nend')
