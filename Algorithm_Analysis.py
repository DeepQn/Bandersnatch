import pyshark


sample_file = input("Enter the file name: ")
sample_file = sample_file + ".pcapng"
initial_range_noh = 5400
final_range_noh = 6800
time_of_1st_choice_cl2 = 171
cl2_capture = pyshark.FileCapture(sample_file,
                                  display_filter="(frame.len > {} && frame.len < {} && frame.time_relative > {})".format(initial_range_noh, final_range_noh, time_of_1st_choice_cl2))

skip_itr = 0
global next_pckt_h, next_type2_pckt

for pckt in cl2_capture:

    if skip_itr > 0:
        skip_itr -= 1
        continue

    current_pckt_time = pckt.frame_info.time_relative

    for next_pckt_h in cl2_capture:
        if current_pckt_time + 10 <= next_pckt_h.frame_info.time_relative <= current_pckt_time + 20:
            break

    if next_pckt_h.ssl.record.length - pckt.ssl.record.length > 500:
        print("Auto clicked")

        skip_itr = 1

    else:
        print("Mouse clicked")

        for next_type2_pckt in cl2_capture:
            if current_pckt_time + 10 <= next_type2_pckt.frame_info.time_relative <= current_pckt_time + 20:
                break

        if 627 <= next_type2_pckt.ssl.record.length <= 628:
            print("Non default choice is selected")

        else:
            print("Default choice is selected")

        skip_itr = 2
