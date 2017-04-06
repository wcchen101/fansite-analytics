import heapq
import re
import time, datetime
import os, sys
from datetime import datetime
cwd = os.getcwd()

def main():
    """
        This is main function for executing the major features

        Feature 1: Get top 10 most visited ip
        Feature 2: Get top 10 most visisted resources
        Feature 3: Get top 10 most frequently visited time in next 60 mins window
        Feature 4: Get the blocked list which contains the records of fail login
        of certain ip followed by 3 times failing login in 20s time window
    """
    # print(parent_path)
    # print(sys.argv[1][1:])
    input_file = open(sys.argv[1], 'r')
    hosts_file = open(sys.argv[2],'w')
    hours_file = open(sys.argv[3], 'w')
    resources_file = open(sys.argv[4], 'w')
    blocks_file = open(sys.argv[5], 'w')
    dict_ip, dict_resource, dict_time, dict_count, blocklist = {}, {}, {}, {},{}
    time_arr, whole_arr = [], []
    timewindow, count, prev_time = 60, 0, None
    while True:
        try:
            for line in input_file:
                words = line.split()
                ip, resource_line, bandwidth = words[0], words[-5:-3], words[-1]
                #use regular expression to find the pattern in certain sentence
                match_time = re.search(r'\[+.*\]+', line)
                match_resource = re.findall(r'/+[\w.-]*', ' '.join(resource_line))
                match_resource = ''.join(match_resource)

                #saving data in cache for feature 1
                if ip not in dict_ip:
                    dict_ip[ip] = 1
                else:
                    dict_ip[ip] += 1

                #saving data in cache for feature 2
                if match_resource and bandwidth.isnumeric():
                    if match_resource == '/':
                        continue
                    if match_resource not in dict_resource:
                        dict_resource[match_resource] = int(bandwidth)
                    else:
                        dict_resource[match_resource] += int(bandwidth)

                #saving data in cache for feature 3, 4
                if match_time:
                    time, ip = match_time.group(), words[0]
                    if time == prev_time:
                        count += 1
                        dict_count[time[1:-1]] = count
                    else:
                        count += 1
                        dict_count[time[1:-1]] = count
                        prev_time = time

                    #saving data in cache for feature 4
                    whole_arr.append(words)
                    time_arr.append([time[1:-1], ip])

                print('.', end = '')

        except (UnicodeDecodeError, IndexError, AttributeError):
            print('Wrong format or something else')
            pass
        else:
            print('Done saving information in cache')
            break
    # #feature1
    get_Topk(dict_ip, 10, hosts_file, True)
    # #feature2
    get_Topk(dict_resource, 10, resources_file, False)
    # feature3
    sliding_window(dict_time, time_arr, 3600, dict_count)
    get_Topk(dict_time, 10, hours_file, True)
    # feature4
    detect_log_anomaly(blocklist, time_arr, 20, whole_arr, blocks_file)
    print('Done all')

def get_Topk(dict, k, filename, writeCount=True):
    """ Get Top k key from certain dictionary using min heap algorithm

        By making the dictionary key, negative value of element into
        a min heap, and then pop it to get the biggest value each time.
        Every times it get the biggest value from heap, it should be followed by
        heapify operation

        Args:
            dict: this is certain dictionary to store the key and value in order
            to find the top k
            k: top k element in the dictionary
            filename: the file name which top k is written in
            write_count: if it needs to be written down the count of the value
            corresponding to each key
    """
    heap = [(-value, key) for key, value in dict.items()]
    heapq.heapify(heap)
    minLen = min(len(dict), k)
    for i in range(minLen):
        topkElement = heapq.heappop(heap)
        if writeCount is False:
            filename.write(str(topkElement[1]) + '\n')
        else:
            filename.write(str(topkElement[1]) + ',' + str(-topkElement[0]) + '\n')
        heapq.heapify(heap)

def get_time(time_input):
    """ This is function to get the timestamp from datetime format.
        Args:
            time_input: the datetime input.
        Returns:
            Returns certain datetime in timestamp format.
            example: 804582015.0
    """
    time_input = time_input.split()[:-1]
    timestamp = time.mktime(time.strptime(time_input[0], '%d/%b/%Y:%H:%M:%S'))
    return timestamp

def convert_timestamp(timestamp):
    """ This is a function to convert timestamp insto datetime format

        Args:
            timestamp: this is the timestamp derived from datetime format

        Returns:
            Returns certain timestamp in datetime format
            example: 01/Jul/1995:00:00:01 -0400
    """
    time_output = datetime.fromtimestamp(timestamp).strftime('%d/%b/%Y:%H:%M:%S -0400')
    return time_output

def time_diff(timebefore, timeafter):
    """ This is the function to get the timestamp
        difference from time before to time after

        Args:
            timebefore: in datetime format
            timeafter:  in datetime format

        Returns:
            Returns difference of timestamp in seconds scale
    """
    time_difference = get_time(timeafter) - get_time(timebefore)
    return time_difference

def sliding_window(dict_time, time_arr, window, dict_count):
    """ Get most frequetly visited in the 60 mins window

        Using the previous saving data strucutre arrau (ex. [[datetime, ip])
        and dictionary (ex. {'datetime': acumulate visitied count})
        to help implement sliding window algorithm.
        It uses sequential time passing from the begenning to the end of the time
        to find the vistied count in window frame by using auxilary count
        dictionary and array with date

        Args:
            dict_time: a dictionary to store a time and corresponding visited time
            in certain window in order to get top k
            time_arr: an prestored array which store corresponding datetime
            and visited ip
            window: a time window which is in seconds scale
            dict_count: a prestored dictionary which save the acumulated
            visited count

        Returns:
            None
    """
    start, stop = get_time(time_arr[0][0]), get_time(time_arr[-1][0])
    window = min(window, stop - start)
    pre_count,post_count = dict_count[time_arr[0][0]],dict_count[time_arr[0][0]]

    while start <= get_time(time_arr[-1][0]):
        start_time = convert_timestamp(start)
        window_time = get_time(time_arr[0][0])+  window
        window_datetime = convert_timestamp(window_time)

        if window_datetime in dict_count:
            post_count = dict_count[window_datetime]

        if start_time in dict_count:
            pre_count = dict_count[start_time]
            dict_time[start_time] = post_count - pre_count + 1
        else:
            dict_time[start_time] = post_count - pre_count

        window_time += 1
        start += 1
        print('.', end = '')

    print('Done sliding window')

def detect_log_anomaly(blocklist, time_arr, window, whole_arr, blocks_file):
    """ This is the function for detecting login anomaly in the 20s windows

        Using sequential time O(N) to detect log anomaly with two prestored
        helper data structure (time_arr, whole_arr) and a blocklist dictionary
        to save the fails count within the certain window for those ip address

        Args:
            blocklist: a blocklist which contains ip which failed login with
            corresponding fails count.
            time_arr: the prestored array which contains ip and time.
            window: a window in seconds scale
            whole_arr: a prestored array keeping all information in array
            which are used with time_arr
            blocks_file: the file that are going to write down the blocked list

        Returns:
                None
    """
    i = 0
    while i < len(time_arr):
        ip1 = whole_arr[i][0]
        protocol1 = whole_arr[i][-2]
        if protocol1 == '200' and ip1 not in blocklist:
            i += 1
            continue
        elif protocol1 == '200' and ip1 in blocklist \
            and time_diff(blocklist[ip1][0], time_arr[i][0]) > window:
            del blocklist[ip1]
            i += 1
            continue
        elif protocol1 == '200' and ip1 in blocklist \
            and time_diff(blocklist[ip1][0], time_arr[i][0]) < window:
            if blocklist[ip1][1] >= 3:
                blocks_file.write(' '.join(whole_arr[i]) + '\n')
            i += 1
            continue
        elif protocol1 == '401' and ip1 in blocklist \
            and time_diff(blocklist[ip1][0], time_arr[i][0]) > window:
            del blocklist[ip1]
            blocklist[ip1] = [time_arr[i][0], 1]
            i += 1
            continue
        elif protocol1 == '401' and ip1 not in blocklist:
            blocklist[ip1] = [time_arr[i][0], 1]
            i += 1
            continue
        elif protocol1 == '401' and ip1 in blocklist \
            and time_diff(blocklist[ip1][0], time_arr[i][0]) < window:
            tryCount = blocklist[ip1][1] + 1
            blocklist[ip1][1] = tryCount
            if tryCount > 3:
                blocks_file.write(' '.join(whole_arr[i]) + '\n')
            i += 1
            continue

        i += 1
        print('.', end = '')

    print('Done detect anomaly log')

if __name__ == '__main__':
    main()
