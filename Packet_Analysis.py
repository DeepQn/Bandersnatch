import pyshark

override_prefs = {'ssl.keylog_file': "Default\\sslkey.log"}

cap = pyshark.FileCapture("Default/Default_Selection.pcapng",
                          display_filter="(ssl.record.content_type==23 && http)",
                          override_prefs=override_prefs)

cap_tcp = pyshark.FileCapture("Default/Default_Selection.pcapng", display_filter="(tcp)")

print("Packets are loading...")
cap.load_packets()
packet_amount = len(cap)

# # # capturing http or application layer response packet # # #

for i in range(packet_amount):
    pckt = cap[i]

    pckt_fr = int(pckt.frame_info.number)
    message = str(pckt.http.chat)
    # msg_index_http = message.index("HTTP")

    if str(pckt.ip.src) == "192.168.7.32":

        if message.find("GET") != -1:
            msg_index_get = message.index("GET")

            print("\n\n\n\nRequested Object No: ", i + 1)
            print("Requested Packet No: ", pckt_fr)
            print("Requested Object: ", message[msg_index_get + len("GET"):])
            print("Requested Packet Length: ", pckt.tls.record_length)
            print("Requested Packet Ack No: ", pckt.tcp.ack, "\n\n")

            for tp in cap:
                if int(tp.tcp.ack) == int(pckt.tcp.nxtseq):
                    if int(tp.tcp.len) == 0:
                        print("Response Packet No: ", tp.frame_info.number)
                        print("Response Packet Length: ", tp.tls.record_length)
                        print("Response Packet Object: ", tp.http.chat)
                    elif int(tp.tcp.len) > 0:
                        print("Response Packet No: ", tp.frame_info.number)
                        print("Response Packet Length: ", tp.tls.record_length)
                        print("Response Packet Object: ", tp.http.chat)
                        break

        elif message.find("POST") != -1:
            msg_index_get = message.index("POST")

            print("\n\n\n\nRequested Object No: ", i + 1)
            print("Requested Packet No: ", pckt_fr)
            print("Requested Object: ", message[msg_index_get + len("POST"):])
            print("Requested Packet Length: ", pckt.tls.record_length)
            print("Requested Packet Ack No: ", pckt.tcp.ack, "\n\n")

            for tp in cap:
                if int(tp.tcp.ack) == int(pckt.tcp.nxtseq):
                    if int(tp.tcp.len) == 0:
                        print("Response Packet No: ", tp.frame_info.number)
                        print("Response Packet Length: ", tp.tls.record_length)
                        print("Response Packet Object: ", tp.http.chat)
                    elif int(tp.tcp.len) > 0:
                        print("Response Packet No: ", tp.frame_info.number)
                        print("Response Packet Length: ", tp.tls.record_length)
                        print("Response Packet Object: ", tp.http.chat)
                        break

        else:

            print("\n\n\n\nRequested Object No: ", i + 1)
            print("Requested Packet No: ", pckt_fr)
            print("Requested Object: ", message)
            print("Requested Packet Length: ", pckt.tls.record_length)
            print("Requested Packet Ack No: ", pckt.tcp.ack, "\n\n")

            for tp in cap:
                if int(tp.tcp.ack) == int(pckt.tcp.nxtseq):
                    if int(tp.tcp.len) == 0:
                        print("Response Packet No: ", tp.frame_info.number)
                        print("Response Packet Length: ", tp.tls.record_length)
                        print("Response Packet Object: ", tp.http.chat)
                    elif int(tp.tcp.len) > 0:
                        print("Response Packet No: ", tp.frame_info.number)
                        print("Response Packet Length: ", tp.tls.record_length)
                        print("Response Packet Object: ", tp.http.chat)
                        break

        print("---------------------------------------------------------------------")

# # # # capturing tcp or transport layer response packet response packet # # #
# num_pckts = 0
# for pckt in cap:
#     num_pckts += 1
#
#     pckt_fr = int(pckt.frame_info.number)
#     message = str(pckt.http.chat)
#     msg_index_http = message.index("HTTP")
#
#     if message.find("GET") != -1:
#         msg_index_get = message.index("GET")
#
#     else:
#         msg_index_get = -(len("GET"))
#
#     if str(pckt.ip.src) == "192.168.7.32":
#
#         print("\n\n\n\nRequested Object No: ", num_pckts)
#         print("Requested Packet No: ", pckt_fr)
#         print("Requested Object: ", message[msg_index_get + len("GET"): msg_index_http - 1])
#         print("Requested Packet Size: ", pckt.tls.record_length)
#         print("Requested Packet Ack No: ", pckt.tcp.ack, "\n\n")
#
#         pckt_ack = int(pckt.tcp.ack)
#         for tp in cap_tcp:
#             if int(tp.tcp.seq) == pckt_ack:
#                 if int(tp.tcp.len) == 0:
#                     print("Response Packet No: ", tp.frame_info.number)
#                     print("Response TCP Segment Length: ", tp.tcp.len)
#                     print("Response Packet Seq No: ", tp.tcp.seq)
#                 elif int(tp.tcp.len) > 0:
#                     print("Response Packet No: ", tp.frame_info.number)
#                     print("Response TCP Segment Length: ", tp.tcp.len)
#                     print("Response Packet Seq No: ", tp.tcp.seq)
#                     break
#
#         print("---------------------------------------------------------------------")
