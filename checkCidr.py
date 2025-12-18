import ipaddress
import sys
import ipAddress
import os
import csv


def find_ip_info_fast(rangeIp_list, input_ip):
    try:
        if "/" in input_ip:
            t_ip = ipaddress.ip_interface(input_ip).ip
            print('in if log',t_ip)
        else:
            t_ip = ipaddress.ip_address(input_ip)
            print('in else log',t_ip)
    except ValueError:
        return {"error": "invalid IP address"}
    t_integer = int(t_ip)

   
    left, right = 0, len(rangeIp_list) - 1
    left_limitation = -1
    while(left <= right):
        pivot = (left + right) //2
        if rangeIp_list[pivot]['network_int'] <= t_integer:
            left_limitation = pivot
            left = pivot + 1
        else:
            right = pivot - 1

    left, right = 0, len(rangeIp_list) - 1
    right_limitation = -1
    while left <= right:
        mid = (left + right) // 2
        if rangeIp_list[mid]['network_int'] <= t_integer:
            right_limitation = mid
            left = mid + 1
        else:
            right = mid - 1
    
    in_range = []
    for i in range(left_limitation,right_limitation + 1):
        if (rangeIp_list[i]['network_int'] <= t_integer <= rangeIp_list[i]['broadcast_int']):
            in_range.append(rangeIp_list[i])
    if not in_range:
        return None
    best_match = min(in_range, key=lambda x: x['prefixlen'])
    return {
            "range": best_match['range'],
            "isp": best_match['isp'],
            "as": best_match['as'],
            "country": best_match['country']
        }

def preprocess_ip_ranges(file_path):
    rangeIp_list = []
    with open(file_path, 'r', encoding='utf-8') as f:
        csv_result = csv.reader(f,skipinitialspace=True)
        for row in csv_result:
            if(len(row) < 4):
                continue

            cidr = row[0].strip()
            isp = row[1]
            as_name = int(row[2])
            country = row[3]

            network = ipaddress.ip_network(cidr, strict=False)

            rangeIp_list.append({
                'network':network,
                'range':cidr,
                'isp':isp,
                'as': as_name,
                'country':country,
                'network_int': int(network.network_address),
                'broadcast_int': int(network.broadcast_address),
                'prefixlen': network.prefixlen
            })
            rangeIp_list.sort(key=lambda item:item['network_int'])
    return rangeIp_list

if __name__ == "__main__":
    input_ip = "1.0.0.1"
    if len(sys.argv) > 1:
        input_ip = sys.argv[1]
    
    directory = os.path.dirname(os.path.abspath(__file__))
    print('directory path::: ', directory)
    file_path = os.path.join(directory, "ranges (2).txt")


    print("filePath", file_path)
    rangeIp_list = preprocess_ip_ranges(file_path)

    print(find_ip_info_fast(rangeIp_list,input_ip))
    # print(rangeIp_list)
