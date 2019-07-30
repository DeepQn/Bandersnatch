import pyshark


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

# function for finding the intervals between which the traffic peaks lie
# Returns the range where the number of get request are maximum.

sample_file = 'Test1/Test1.pcapng'
source_ip = '192.168.1.238'
dest_ip = '54.194.132.188'

# initial range (ssl record length) of cl2 json files
initial_range_cl2_noh = 4500

# final range (ssl record length) of cl2 json files
final_range_cl2_noh = 7000

# expected time of arrival of cl2 json for the first question
time_of_1st_choice_cl2 = 158

# capturing application data files within the initial_range_cl2_noh and final_range_cl2_noh
cl2_json_capture = pyshark.FileCapture(sample_file,
                                       display_filter="(ssl.record.content_type==23 && ssl.record.length > {} && ssl.record.length < {} && frame.time_relative > {} && ip.src=={} && ip.dst=={})".format(
                                           initial_range_cl2_noh, final_range_cl2_noh, time_of_1st_choice_cl2,
                                           source_ip, dest_ip))

# initial range (ssl record length) of server-site (Type1 and Type2) json files
initial_range_server_noh = 2025

# final range (ssl record length) of server-site (Type1 and Type2) json files
final_range_server_noh = 2038

# expected time of arrival of the first question
time_of_1st_choice_server = 158

# capturing application data files within the initial_range_server_noh and final_range_server_noh
server_json_capture = pyshark.FileCapture(sample_file,
                                          display_filter="(ssl.record.content_type==23 && ip.dst=={} && ip.src=={} && frame.time_relative > {} && ssl.record.length > {} && ssl.record.length < {})".format(
                                              source_ip, dest_ip, time_of_1st_choice_server, initial_range_server_noh,
                                              final_range_server_noh))

# initializing global variables
global next_pckt_h, next_type2_pckt, non_default_flag

for server_json in server_json_capture:
    if 2035 <= float(server_json.ssl.record_length) <= 2038:
        server_json_time = float(server_json.frame_info.time_relative)
        print("Type1 Json:", server_json_time)
        previous_flag = False

        for pckt in cl2_json_capture:
            # condition for considering the packets which has ssl record length in between initial_range_cl2_noh
            # and final_range_cl2_noh
            if server_json_time - 15 < float(
                    pckt.frame_info.time_relative) < server_json_time - 10 and initial_range_cl2_noh < int(
                    pckt.ssl.record_length) < final_range_cl2_noh:
                previous_flag = True
                print("Question:", pckt.frame_info.time_relative)

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
                        if current_pckt_time + 10 <= float(
                                next_type_pckt.frame_info.time_relative) <= current_pckt_time + 20:

                            # check ssl record length to identify the packet as Type1 json
                            if 2026 <= float(next_type_pckt.ssl.record_length) <= 2037:
                                # if found any Type1 json then auto-click occurred
                                print("Auto clicked-> Frame No: ", pckt.frame_info.number, end="\n\n")

                else:
                    # if the difference is less than 600 then mouse-click occurred
                    print("Mouse clicked-> Frame No: ", pckt.frame_info.number)

                    # capture server-site json files captured immediately after the current cl2 json
                    for next_type2_pckt in server_json_capture:
                        non_default_flag = False

                        # if any Type2 json is found then non-default choice is selected
                        if current_pckt_time + 10 <= float(
                                next_type2_pckt.frame_info.time_relative) <= current_pckt_time + 20:
                            if 2026 <= float(next_type2_pckt.ssl.record_length) <= 2030:
                                print("Non default choice is selected", end="\n\n")
                                non_default_flag = True
                                break

                    # if only Type1 json file is captured then default choice is selected
                    if not non_default_flag:
                        print("Default choice is selected", end="\n\n")
                        break
                        # for next_type1_pckt in server_json_capture:
                        #     if current_pckt_time + 10 <= float(
                        #             next_type1_pckt.frame_info.time_relative) <= current_pckt_time + 20:
                        #         if 2035 <= float(next_type1_pckt.ssl.record_length) <= 2038:
                        #             print("Default choice is selected", end="\n\n")
                        #             break

        if not previous_flag:
            print("Previous choice was default", end="\n\n")
