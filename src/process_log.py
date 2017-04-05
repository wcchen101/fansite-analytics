import heapq
import re
import time, datetime
import os, sys
from tempfile import mkstemp
from datetime import datetime
cwd = os.getcwd()
parent_path = os.path.abspath(os.path.join(cwd, os.pardir))
temp_path = parent_path +'/temp'

def main():
    """
        This is main function for executing the major features

        Feature 1: Get top 10 most visited ip
        Feature 2: Get top 10 most visisted resources
        Feature 3: Get top 10 most frequently visited time in the next 60 mins
        Feature 4: Get the blocked list which contains the records of failing login
        of certain ip followed by 3 times failing login in certain time window

    """
    input_file = open(temp_path+ '/'+ 'log_input/'+'log.txt', 'r')
    blocks_file = open(temp_path + '/'+ 'log_output/' + 'blocked.txt', 'w')
    hours_file = open(temp_path + '/'+ 'log_output/' + 'hours.txt', 'w')
    hosts_file = open(temp_path + '/'+ 'log_output/'+'hosts.txt','w')
    resources_file = open(temp_path+ '/'+ 'log_output/'+ 'resources.txt', 'w')
    dict_ip = {}
    dict_resource = {}
    dict_time = {}
    blocklist = {}
    time_arr = []
    whole_arr = []
    timewindow = 60
    while True:
        try:
            for line in input_file:
                words = line.split()
                # match_ip = re.search(r'([\w.-]+[.]*[\w.-])', line)
                # match_resource = re.search(r'([/]+[\w.-]*[/]*)', resource_line)
                resource_line = words[-4]
                match_time = re.search(r'\[+.*\]+', line)
                bandwidth = words[-1]
                ip = words[0]
                #saving data for feature 1
                if ip not in dict_ip:
                    dict_ip[ip] = 1
                else:
                    dict_ip[ip] += 1

                #saving data for feature 2
                if bandwidth.isnumeric():
                    if resource_line == '/':
                        continue
                    if resource_line not in dict_resource:
                        dict_resource[resource_line] = int(bandwidth)
                    else:
                        dict_resource[resource_line] += int(bandwidth)

                #saving data for feature 3
                if match_time:
                    time, ip = match_time.group(), words[0]
                    whole_arr.append(words)
                    time_arr.append([time[1:-1], ip])

                print('.', end = '')

        except (UnicodeDecodeError, IndexError):
            print('wrong format or something else')
            pass
        else:
            print('Done saving information in cache')
            break

    # #feature1
    get_Topk(dict_ip, 10, hosts_file, True)
    # #feature2
    get_Topk(dict_resource, 10, resources_file, False)
    # feature3
    sliding_window(dict_time, time_arr, 3600)
    get_Topk(dict_time, 10, hours_file, True)
    # feature4
    detect_log_anomaly(blocklist, time_arr, 20, whole_arr, blocks_file)
    print('done all')

def get_Topk(dict, k, filename, writeCount=True):
    """ Get Top k key from certain dictionary using min heap algorithm
        Args:
            dict: this is the dictionary to store the key and value in order to
            \find the top k
            k: top k element in the dictionary
            filename: the file name which top k is written in
            write_count: if it needs to be written down the count of the value
            corresponding to each key
    """
    heap = [(-value, key) for key, value in dict.items()]
    heapq.heapify(heap)
    topkArr = []
    minLen = min(len(dict), k)
    for i in range(minLen):
        topkElement = heapq.heappop(heap)
        topkArr.append((topkElement[1], -topkElement[0]))
        if writeCount is False:
            filename.write(str(topkElement[1]) + '\n')
        else:
            filename.write(str(topkElement[1]) + ',' + str(-topkElement[0]) + '\n')
        heapq.heapify(heap)

    # topkArr = sorted(topkArr, key=lambda value:value[1], reverse=True)
    # return topkArr

def get_time(time_input):
    """ This is function to get the timestamp from datetime format
        Args:
            time_input: the datetime input
        Returns:
            Returns certain datetime in timestamp format
    """
    time_input = time_input.split()[:-1]
    timestamp = time.mktime(time.strptime(time_input[0], '%d/%b/%Y:%H:%M:%S'))
    return timestamp

def convert_timestamp(timestamp):
    """ This is a function to convert timeestamp to datetime format

        Args:

        Returns:
            Returns certain timestamp in datetime format
    """
    time_output = datetime.fromtimestamp(timestamp).strftime('%d/%b/%Y:%H:%M:%S -0400')
    return time_output

def time_diff(timebefore, timeafter):
    """ This is the function to get the timestamp difference from timebefore to timeafter

        Args:
            timebefore: in datetime format
            timeafter:  in datetime format
        Returns:
            Returns difference of timestamp in seconds scale
    """
    time_difference = get_time(timeafter) - get_time(timebefore)
    return time_difference

def sliding_window(dict_time, time_arr, window):
    """ Get most frequetly visited in the 60 mins window

        Using the previous saving array (ex. [[datetime, ip]]) to implement sliding
        window algorithm. It has expensive time complexity but may be relief by scaling
        out the system

        Args:
            dict_time: a dictionary to store a time and corresponding visited time
                in certain window
            time_arr: an prestored array which store corresponding datetime and visited ip
            window: a time window which is in seconds scale

        Returns:
            None
    """
    start = get_time(time_arr[0][0])
    stop = get_time(time_arr[-1][0])
    i = 0
    prevTime = time_arr[0][0]
    while start <= stop:
        startTime = convert_timestamp(start)
        dict_time[startTime] = 0
        if i + 1 < len(time_arr) and start > get_time(prevTime):
            i += 1
            prevTime = time_arr[i][0]

        j = i
        while j < len(time_arr) and get_time(time_arr[j][0]) - start < window:
            dict_time[startTime] += 1
            j += 1
        start += 1
    print('Done sliding window')

def detect_log_anomaly(blocklist, time_arr, window, whole_arr, blocks_file):
    """ This is the function for detection login anomaly in the certain windows

        Using sequential time O(N) to detect log anomaly with two prestored helper data structure
        (time_arr, whole_arr) and a blocklist dictionary to save the fails count
        in the certain window for those ip address

        Args:
            blocklist: a blocklist which contains ip which failed login with corresponding fails count.
            time_arr: the prestored array which contains ip and time.
            window: a window in seconds scale
            whole_arr: a prestored array storing all information which use with time_arr
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
        elif protocol1 == '200' and ip1 in blocklist and time_diff(blocklist[ip1][0], time_arr[i][0]) > window:
            del blocklist[ip1]
            i += 1
            continue
        elif protocol1 == '200' and ip1 in blocklist and time_diff(blocklist[ip1][0], time_arr[i][0]) < window:
            if blocklist[ip1][1] >= 3:
                blocks_file.write(' '.join(whole_arr[i]) + '\n')
            i += 1
            continue
        elif protocol1 != '200' and ip1 in blocklist and time_diff(blocklist[ip1][0], time_arr[i][0]) > window:
            del blocklist[ip1]
            blocklist[ip1] = [time_arr[i][0], 1]
            i += 1
            continue
        elif protocol1 != '200' and ip1 not in blocklist:
            blocklist[ip1] = [time_arr[i][0], 1]
            i += 1
            continue
        elif protocol1 != '200' and ip1 in blocklist and time_diff(blocklist[ip1][0], time_arr[i][0]) < window:
            tryCount = blocklist[ip1][1] + 1
            blocklist[ip1][1] = tryCount
            if tryCount > 3:
                blocks_file.write(' '.join(whole_arr[i]) + '\n')
            i += 1
            continue
        i += 1

    print('done detect anomaly log')

if __name__ == '__main__':
    main()
