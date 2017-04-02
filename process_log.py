import heapq
import re
import time, datetime
heap = []

def main():
    bufferSize = 50000
    inputFile = open('log.txt', 'r')
    outputFile = open('output.txt', 'w')
    dict_ip = {}
    dict_resource = {}

    while True:
        try:
            # while len(buffer):
            for line in inputFile:
                match_ip = re.search(r'\w+[.]+\w+[.]+\w+[.]+\w', line)
                match_resource = re.search(r'([/]+[\w.-]+[/]*)+\.\w+', line)

                # #feature 1
                if match_ip:
                    ip = match_ip.group()
                    if ip not in dict_ip:
                        dict_ip[ip] = 1
                    else:
                        dict_ip[ip] += 1

                print('.', end = '')
                # #feature 2
                if match_resource and bandwidth.isnumeric():
                    resource = match_resource.group()
                    if resource == '/1.0':
                        continue
                    if resource not in dict_resource:
                        dict_resource[resource] = int(bandwidth)
                    else:
                        dict_resource[resource] += int(bandwidth)


                print('.', end = '')

        except UnicodeDecodeError:
            print('wrong format or something else')
            continue
        else:
            print('Done')
            break

    print('done2')

def getTopk(dict, k):
    heap = [(-value, key) for key, value in dict.items()]
    heapq.heapify(heap)
    topk_arr = []
    for i in range(k):
        topkelement = heapq.heappop(heap)
        topk_arr.append((topkelement[1], -topkelement[0]))
        heapq.heapify(heap)
    topk_arr = sorted(topk_arr, key=lambda value:value[1], reverse=True)
    return topk_arr


if __name__ == '__main__':
    main()
