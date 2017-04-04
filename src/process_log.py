import heapq
import re
import time, datetime
import os, sys
from tempfile import mkstemp
from datetime import datetime
import calendar
heap = []
cwd = os.getcwd()
parentPath = os.path.abspath(os.path.join(cwd, os.pardir))
tempPath = parentPath +'/temp'

def main():
    bufferSize = 50000
    inputFile = open(parentPath+ '/'+ 'log_input/'+'log.txt', 'r')
    blockedFile = open(parentPath + '/'+ 'log_output/' + 'blocked.txt', 'w')
    hoursFile = open(parentPath + '/'+ 'log_output/' + 'hours.txt', 'w')
    hostFile = open(parentPath + '/'+ 'log_output/'+'hosts.txt','w')
    resourceFile = open(parentPath+ '/'+ 'log_output/'+ 'resources.txt', 'w')
    dict_ip = {}
    dict_resource = {}
    dict_time = {}
    blocklist = {}
    time_arr = []
    whole_arr = []
    timewindow = 60
    while True:
        try:
            for line in inputFile:
                words = line.split()
                match_ip = re.search(r'([\w.-]+[.]*[\w.-])', line)
                resource_line = words[-4]
                match_resource = re.search(r'([/]+[\w.-]*[/]*)', resource_line)
                match_time = re.search(r'\[+.*\]+', line)
                bandwidth = words[-1]

                #feature 1
                if match_ip:
                    ip = match_ip.group()
                    if ip not in dict_ip:
                        dict_ip[ip] = 1
                    else:
                        dict_ip[ip] += 1

                #feature 2
                if match_resource and bandwidth.isnumeric():
                    resource = resource_line
                    if resource_line == '/':
                        continue
                    if resource_line not in dict_resource:
                        dict_resource[resource] = int(bandwidth)
                    else:
                        dict_resource[resource] += int(bandwidth)

                #feature 3
                if match_time and match_ip and match_resource:
                    time, ip, resource = match_time.group(), match_ip.group(), match_resource.group()
                    # print(time[1:-1])
                    whole_arr.append(words)
                    time_arr.append([time[1:-1], ip])
                print('.', end = '')

        except (UnicodeDecodeError, IndexError):
            print('wrong format or something else')
            pass
        else:
            print('Done')
            break

    #feature1
    getTopk(dict_ip, 10, hostFile, True)
    #feature2
    getTopk(dict_resource, 10, resourceFile, False)
    # feature3
    slidingWindow(dict_time, time_arr, 3600)
    getTopk(dict_time, 10, hoursFile, True)
    #feature4
    detectLogInAnomly(blocklist, time_arr, 20, whole_arr, blockedFile)
    print('done all')

def getTopk(dict, k, filename, writeCount=True):
    heap = [(-value, key) for key, value in dict.items()]
    heapq.heapify(heap)
    topk_arr = []
    minLen = min(len(dict), k)
    for i in range(minLen):
        topkelement = heapq.heappop(heap)
        topk_arr.append((topkelement[1], -topkelement[0]))
        if writeCount is False:
            filename.write(str(topkelement[1]) + '\n')
        else:
            filename.write(str(topkelement[1]) + ',' + str(-topkelement[0]) + '\n')
        heapq.heapify(heap)

    # topk_arr = sorted(topk_arr, key=lambda value:value[1], reverse=True)
    # return topk_arr

def getTime(timeinput):
    timeinput = timeinput.split()[:-1]
    timestamp = time.mktime(time.strptime(timeinput[0], '%d/%b/%Y:%H:%M:%S'))
    return timestamp

def convertTimeStamp(timestamp):
    timeoutput = datetime.fromtimestamp(timestamp).strftime('%d/%b/%Y:%H:%M:%S -0400')
    return timeoutput

def timeDiff(timebefore, timeafter):
    timeDifference = getTime(timeafter) - getTime(timebefore)
    return timeDifference

def slidingWindow(dict_time, time_arr, window):
    start = getTime(time_arr[0][0])
    stop = getTime(time_arr[-1][0])
    i = 0
    prevtime = time_arr[0][0]
    while start <= stop:
        startTime = convertTimeStamp(start)
        dict_time[startTime] = 0
        if i + 1 < len(time_arr) and start > getTime(prevtime):
            i += 1
            prevtime = time_arr[i][0]

        j = i
        while j < len(time_arr) and getTime(time_arr[j][0]) - start < window:
            dict_time[startTime] += 1
            j += 1
            print('.', end = '')
        start += 1
    print('Done sliding window')

def detectLogInAnomly(blocklist, time_arr, window, whole_arr, blockedFile):
    i = 0
    while i < len(time_arr):
        ip1 = whole_arr[i][0]
        protocol1 = whole_arr[i][-2]
        if protocol1 == '200' and ip1 not in blocklist:
            i += 1
            continue
        elif protocol1 == '200' and ip1 in blocklist and timeDiff(blocklist[ip1][0], time_arr[i][0]) > window:
            del blocklist[ip1]
            i += 1
            continue
        elif protocol1 == '200' and ip1 in blocklist and timeDiff(blocklist[ip1][0], time_arr[i][0]) < window:
            if blocklist[ip1][1] >= 3:
                blockedFile.write(' '.join(whole_arr[i]) + '\n')
            i += 1
            continue
        elif protocol1 != '200' and ip1 in blocklist and timeDiff(blocklist[ip1][0], time_arr[i][0]) > window:
            del blocklist[ip1]
            blocklist[ip1] = [time_arr[i][0], 1]
            i += 1
            continue
        elif protocol1 != '200' and ip1 not in blocklist:
            blocklist[ip1] = [time_arr[i][0], 1]
            i += 1
            continue
        elif protocol1 != '200' and ip1 in blocklist and timeDiff(blocklist[ip1][0], time_arr[i][0]) < window:
            tryCount = blocklist[ip1][1] + 1
            blocklist[ip1][1] = tryCount
            if tryCount > 3:
                blockedFile.write(' '.join(whole_arr[i]) + '\n')
            i += 1
            continue
        i += 1

    print('done detect anomly log')

if __name__ == '__main__':
    main()
