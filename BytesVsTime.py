import pyshark
import matplotlib.pyplot as plt
import pickle

# override_prefs = {'ssl.keylog_file': "Default\\Default_sslkey2.log"}
#
# cap = pyshark.FileCapture("Default/Default_Selection2.pcapng",
#                           display_filter="(ssl.record.content_type==23 && tls)",
#                           override_prefs=override_prefs)

override_prefs = {'ssl.keylog_file': "Non_Default\\Trace6\\sslkey.log"}

cap = pyshark.FileCapture("Non_Default\\Trace6\\non_default6.pcapng",
                          display_filter="(ssl.record.content_type==23 && tls)",
                          override_prefs=override_prefs)

# print("Packets are loading...")
# cap.load_packets()
# packet_amount = len(cap)
# print("Total packets: ", packet_amount)

time_seq_list = []
byte_len_list = []
packet_len_list = []

# # # capturing http or application layer response packet # # #

time_seq = 0
for pckt in cap:
    time_seq = float(pckt.frame_info.time_relative)

    if len(time_seq_list) == 0:
        byte_len = float(pckt.tls.record_length)
        # packet_len = float(pckt.ip.len)
    else:
        if time_seq == time_seq_list[-1]:
            byte_len = float(pckt.tls.record_length) + byte_len_list[-1]
            # packet_len = float(pckt.ip.len) + packet_len_list[-1]
            continue
        else:
            byte_len = float(pckt.tls.record_length)
            # packet_len = float(pckt.ip.len)

    time_seq_list.append(time_seq)
    byte_len_list.append(byte_len)
    # packet_len_list.append(packet_len)

fig1 = plt.figure(1)
plt.plot(time_seq_list, byte_len_list, linewidth=0.5, color='green')
plt.title("Non Default Selection Bytes vs Time Plot")
plt.xlabel("time")
plt.ylabel("Bytes")
plt.show()
