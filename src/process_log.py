import heapq
import re
import time, datetime
import os, sys
from tempfile import mkstemp
heap = []
cwd = os.getcwd()
parentPath = os.path.abspath(os.path.join(cwd, os.pardir))
tempPath = parentPath +'/temp'

def main():
    bufferSize = 50000
    inputFile = open(tempPath+ '/'+ 'log_input/'+'log.txt', 'r')
    blockedFile = open('blocked.txt', 'w')
    hoursFile = open('hours.txt', 'w')
    hostFile = open(tempPath + '/'+ 'log_output/'+'hosts.txt','w')
    resourceFile = open(tempPath+ '/'+ 'log_output/'+ 'resources.txt', 'w')
    dict_ip = {}
    dict_resource = {}
    dict_time = {}
    block_list = {}
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
                    print(ip)
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
                    whole_arr.append(words)
                    time_arr.append([time[1:-1], ip])
                print('.', end = '')

        except UnicodeDecodeError:
            print('wrong format or something else')
            continue
        else:
            print('Done')
            break

    #feature1
    getTopk(dict_ip, 10, hostFile, True)
    print(dict_ip)
    #feature2
    getTopk(dict_resource, 10, resourceFile, False)
    print(dict_resource)
    #feature3
    # slidingWindow(dict_time, time_arr, 60)
    # getTopk(dict_time, 10, hoursFile)
    #feature4
    # detectLogInAnomly(blocklist, time_arr, 20, whole_arr, blockedFile)
    print('done all')

def getTopk(dict, k, filename, writeCount=True):
    heap = [(-value, key) for key, value in dict.items()]
    heapq.heapify(heap)
    topk_arr = []

    for i in range(len(dict)):
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


def slidingWindow(dict_time, time_arr, window):
    i = 0
    while i < len(time_arr):
        val1 = getTime(time_arr[i][0])
        dict_time[time_arr[i][0]] = 1
        j = i + 1
        while j < len(time_arr):
            val2 = getTime(time_arr[j][0])
            if val2 - val1 > window:
                break
            else:
                dict_time[time_arr[i][0]] += 1
            print('.', end = '')
            j += 1
        i += 1
    print('Done sliding window')

def detectLogInAnomly(blocklist, time_arr, window, whole_arr, blockedFile):
    i, j = 0, 1
    while i < len(time_arr):
        ip1 = whole_arr[i][0]
        protocol1 = whole_arr[i][-2]
        val1 = getTime(time_arr[i][0])
        if protocol1 == '200':
            i += 1
            continue
        #logIn fails
        tryCount = 1
        blocklist[time_arr[i][0]] = (time_arr[i][0], tryCount)
        j = i + 1
        while j < len(time_arr):
            val2 = getTime(time_arr[j][0])
            ip2 = whole_arr[j][0]
            protocol2 = whole_arr[j][-2]
            if val2 - val1 > window:
                del blocklist[time_arr[i][0]]
                break
            elif val2 - val1 < window and ip1 == ip2:
                if protocol2 == '200' and time_arr[i][0] in blocklist:
                    del blocklist[time_arr[i][0]]
                    tryCount = 0
                    break

                elif protocol2 != '200':
                    tryCount += 1
                    blocklist[time_arr[i][0]] = (time_arr[i][0], tryCount)
                    if tryCount > 3:
                        #write ip block to the file
                        blockedFile.write(' '.join(whole_arr[j]) + '\n')
            j += 1
            # print('.', end = '')
        i += 1
    print('done detect anomly log')

if __name__ == '__main__':
    main()
