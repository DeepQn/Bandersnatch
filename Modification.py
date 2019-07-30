import os

import pyshark
from math import *
import pandas as pd
import csv


# convert a list into a string
def convert(s):
    new = ""
    for x in s:
        new += x

    return new


# taking pcapng file name as user input and store into sample_file
# sample_file = input("Enter the file name: ")
# sample_file = sample_file + ".pcapng"

# # finding the indexes where '\' is present in the string
# bcksl_list = [j for j, n in enumerate(sample_file) if n == "\\"]

# # converting a '\' into '\\' so that string operations can be performed properly
# sample_file = list(sample_file)
# for index in bcksl_list:
#     sample_file[index] = "\\\\"

# # converting the a list into a string with the help of convert() function
# sample_file = convert(sample_file)

# # taking client ip as user input
# source_ip = input("Enter your source ip: ")  # "192.168.1.238"

# # taking server ip as user input
# dest_ip = input("Enter netflix server ip: ")  # '45.57.51.132'

'''['No', 'Time', 'Source', 'Destination', 'tls_len', 'Info']'''
# function for finding the intervals between which the traffic peaks lie
# Returns the range where the number of get request are maximum.

sample_file = 'Test2/Test2.pcapng'
source_ip = '192.168.7.32'
dest_ip = '34.250.41.147'


def Find_Peak(pcap_file="../firefox03/firefox03.raw", csv_file="../firefox03/firefox03.csv", th=350):
    """
    pcap_file : pcapng file location
    csv_file : csv file location
    nf_ip : Netflix IP
    """

    global startTime
    if not os.path.exists(csv_file):  # check if the csv is already present
        # tshark comand to create the csv
        tshark_cmd = 'tshark -T fields -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.tls_len -e _ws.col.Info -E header=y -E separator="\t" -E quote=d -E occurrence=f -r {} > {}'.format(
            pcap_file, csv_file)
        os.system(tshark_cmd)  # executing the cmd

        # loading the csv file in pandas dataframe
        pcap_main = pd.read_csv(csv_file, sep="\t", index_col=None, encoding='utf-8')
        # renaming the column names
        pcap_main.rename(index=str, columns={"_ws.col.No.": "No", "_ws.col.Time": "Time", "_ws.col.Source": "Source",
                                             "_ws.col.Destination": "Destination", "_ws.col.tls_len": "tls_len",
                                             "_ws.col.Info": "Info"}, inplace=True)

    else:
        pcap_main = pd.read_csv(csv_file, sep=",", index_col=None, encoding='utf-8')

    pcap_main.rename(columns={pcap_main.columns[0]: 'No',
                              pcap_main.columns[1]: 'Time',
                              pcap_main.columns[2]: 'Source',
                              pcap_main.columns[3]: 'Destination',
                              pcap_main.columns[4]: 'tls_len'},
                     inplace=True)

    # getting the local ip
    local_ip = pcap_main['Destination'].value_counts().idxmax()
    # getting the netflix ip
    nf_ip = pcap_main['Source'].value_counts().idxmax()

    # filtering the GET requests
    pcap_get = pcap_main[pcap_main['Destination'] == nf_ip]

    pkt_cnt = [0]  # number of Packets at i'th sec
    d_time = []  # list of time
    # start time of the first packet
    start_time = floor(pcap_get.iloc[0, 1])

    i = 0  # count variable
    d_time.append(start_time)  # add the start time to time list

    for _, packet in pcap_get.iterrows():
        curr_time = floor(packet.Time)
        if curr_time > start_time:
            i += 1
            pkt_cnt.append(0)
            d_time.append(curr_time)
            start_time = curr_time
        pkt_cnt[i] += 1

    # Finding peaks
    delta = 0
    th = th  # threshold
    peaks = []  # May contain duplicates
    for i in range(1, len(pkt_cnt)):
        delta = pkt_cnt[i] - pkt_cnt[i - 1]
        if delta > th:
            startTime = d_time[i]
        elif delta < -th:
            endTime = d_time[i]
            peaks.append([startTime - 2, endTime + 2])

    # range with no duplicates
    f_peaks = []  # Final peaks with hopefully no duplicates
    for i in range(len(peaks) - 1):
        if peaks[i][0] != peaks[i + 1][0]:
            f_peaks.append(peaks[i])
    f_peaks.append(peaks[i + 1])

    return f_peaks


# converting a pcapng file into CSV format
def Create_CSV(source_ip, file):
    # using source ip address to filter out the packets
    ip_addr = source_ip

    # loading packets from saved pcapng file
    print("Loading packets...")

    # filter out the packets which are only transferred to or from the client ip
    capture_summary = pyshark.FileCapture(file,
                                          display_filter="(ip.dst=={} or ip.src=={})".format(ip_addr, ip_addr),
                                          only_summaries=True)  # only packets summary are captured for
    #  extracting the 'info' part

    # total packets information is captured
    capture = pyshark.FileCapture(file,
                                  display_filter="(ip.dst=={} or ip.src=={})".format(ip_addr, ip_addr))

    # list to store frame numbers
    frame_no_list = []

    # list to store relative times
    relative_time_list = []

    # list to store source ip addresses
    src_ip_list = []

    # list to store destination ip addresses
    dst_ip_list = []

    # list to store ssl record lengths
    ssl_record_length_list = []

    # list to store info of the packets
    info_list = []

    print("Packets Loaded")

    # extracting the information for creating CSV files
    print("Preparing packets for CSV file...")

    # loop for iterating through the captured packets and packet summary
    for pckt, pckt_summ in zip(capture, capture_summary):

        # extracting the frame number and storing into the frame_no_list
        frame_no_list.append(str(pckt.frame_info.number))

        # extracting the relative times and storing into the frame_no_list
        relative_time_list.append(str(pckt.frame_info.time_relative))

        # extracting the source ip and storing into src_ip_list
        src_ip_list.append(str(pckt.ip.src))

        # extracting the destination ip and storing into dst_ip_list
        dst_ip_list.append(str(pckt.ip.dst))

        # extracting the information and storing into the info_list
        info_list.append(str(pckt_summ.info))

        # extracting only the packets which have ssl layer
        if str(pckt.layers[-1].layer_name) == "ssl":
            try:
                ssl_record_length_list.append((str(pckt.ssl.record_length)))
            except AttributeError:  # putting a value of -1 which has ssl layer but no information under it
                ssl_record_length_list.append(str(-1))
        else:
            ssl_record_length_list.append(str(-1))  # putting a value of -1 which has no ssl layer

    # creating CSV header
    header_row = ['No', 'Time', 'Source', 'Destination', 'tls_len', 'Info']

    print("Creating CSV file...")

    # inserting necessary information into CSV files
    with open('packets.csv', 'a') as csvFile:
        writer = csv.writer(csvFile)
        writer.writerow(header_row)

        for i in range(len(frame_no_list)):
            # creating rows corresponding to the sequence of the header elements
            row = [frame_no_list[i], relative_time_list[i], src_ip_list[i], dst_ip_list[i], ssl_record_length_list[i],
                   info_list[i]]

            # appending rows into the CSV file
            writer.writerow(row)

    # session of CSV file pointer is closed
    csvFile.close()
    print("CSV file is created")

    return './packets.csv'


if not os.path.exists('./packets.csv'):
    # converting pcapng file into CSV file
    csv_file = Create_CSV(source_ip=source_ip, file=sample_file)
else:
    csv_file = './packets.csv'

# getting the peak-interval list with Find_Peak() function
interval_list = Find_Peak(pcap_file=sample_file, csv_file=csv_file, th=350)

# initial range (ssl record length) of cl2 json files
initial_range_cl2_noh = 4500

# final range (ssl record length) of cl2 json files
final_range_cl2_noh = 7000

# expected time of arrival of cl2 json for the first question
time_of_1st_choice_cl2 = 163
# finding cl2 json files which are sent from client
src_addr_cl2 = source_ip

# capturing application data files within the initial_range_cl2_noh and final_range_cl2_noh
cl2_json_capture = pyshark.FileCapture(sample_file,
                                       display_filter="(ssl.record.content_type==23 && ssl.record.length > {} && ssl.record.length < {} && frame.time_relative > {} && ip.src=={})".format(
                                           initial_range_cl2_noh, final_range_cl2_noh, time_of_1st_choice_cl2,
                                           src_addr_cl2))

# initial range (ssl record length) of server-site (Type1 and Type2) json files
initial_range_server_noh = 2026

# final range (ssl record length) of server-site (Type1 and Type2) json files
final_range_server_noh = 2038

# expected time of arrival of the first question
time_of_1st_choice_server = 163

# finding server-site (Type1 and Type2) json files which are sent to client
dst_addr_server = source_ip

# capturing application data files within the initial_range_server_noh and final_range_server_noh
server_json_capture = pyshark.FileCapture(sample_file,
                                          display_filter="(ssl.record.content_type==23 && ip.dst=={} && frame.time_relative > {} && ssl.record.length > {} && ssl.record.length < {})".format(
                                              dst_addr_server, time_of_1st_choice_server, initial_range_server_noh,
                                              final_range_server_noh))

# initializing global variables
global next_pckt_h, next_type2_pckt, non_default_flag

for server_json in server_json_capture:
    if 2036 <= float(server_json.ssl.record_length) <= 2038:
        server_json_time = float(server_json.frame_info.time_relative)

        for pckt in cl2_json_capture:
            # condition for considering the packets which has ssl record length in between initial_range_cl2_noh
            # and final_range_cl2_noh
            if server_json_time-20 < float(pckt.frame_info.time_relative) < server_json_time-15 and initial_range_cl2_noh < int(pckt.ssl.record_length) < final_range_cl2_noh:

                # extracting relative time
                current_pckt_time = float(pckt.frame_info.time_relative)

                for next_pckt_h in cl2_json_capture:

                    # trying to capture the cl2 json files which come after the choice selection-time is over
                    if current_pckt_time + 12 < float(next_pckt_h.frame_info.time_relative) < current_pckt_time + 20:
                        break

                # check the difference of the ssl record length between the next cl2 json after the choice
                # selection-time and the cl2 json corresponding to the question appearance
                if float(next_pckt_h.ssl.record_length) - float(pckt.ssl.record_length) > 600:
                    for next_type_pckt in server_json_capture:

                        # if the above mentioned difference is greater than 600 then check for if any server-site
                        # json files appear
                        if current_pckt_time + 10 <= float(next_type_pckt.frame_info.time_relative) <= current_pckt_time + 20:

                            # check ssl record length to identify the packet as Type1 json
                            if 2027 <= float(next_type_pckt.ssl.record_length) <= 2037:
                                # if found any Type1 json then auto-click occurred
                                print("Auto clicked-> Frame No: ", pckt.frame_info.number, end="\n\n")

                else:
                    # if the difference is less than 600 then mouse-click occurred
                    print("Mouse clicked-> Frame No: ", pckt.frame_info.number)

                    # capture server-site json files captured immediately after the current cl2 json
                    for next_type2_pckt in server_json_capture:
                        non_default_flag = False

                        # if any Type2 json is found then non-default choice is selected
                        if current_pckt_time + 10 <= float(next_type2_pckt.frame_info.time_relative) <= current_pckt_time + 20:
                            if 2027 <= float(next_type2_pckt.ssl.record_length) <= 2030:
                                print("Non default choice is selected", end="\n\n")
                                non_default_flag = True
                                break

                    # if only Type1 json file is captured then default choice is selected
                    if not non_default_flag:
                        for next_type1_pckt in server_json_capture:
                            if current_pckt_time + 10 <= float(
                                    next_type1_pckt.frame_info.time_relative) <= current_pckt_time + 20:
                                if 2036 <= float(next_type1_pckt.ssl.record_length) <= 2038:
                                    print("Default choice is selected", end="\n\n")
                                    break

