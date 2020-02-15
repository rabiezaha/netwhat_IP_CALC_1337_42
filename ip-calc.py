import re

list_of_masks = [pow(2, 7),
                pow(2, 7) + pow(2, 6),
                pow(2, 7) + pow(2, 6) + pow(2, 5),
                pow(2, 7) + pow(2, 6) + pow(2, 5) + pow(2, 4),
                pow(2, 7) + pow(2, 6) + pow(2, 5) + pow(2, 4) + pow(2, 3),
                pow(2, 7) + pow(2, 6) + pow(2, 5) + pow(2, 4) + pow(2, 3) + pow(2, 2),
                254,
                255]
def cidr_to_mask(mask):
    result = ['0', '0', '0', '0']
    ind = int(int(mask) / 8)
    rest = int(int(mask) % 8)
    if rest > 0 :
        ind = ind + 1
    for i in range(0, ind):
        if rest != 0 and i == ind - 1:
            result[i] = str(list_of_masks[rest - 1])
            break
        result[i] = str(255)
    return result
def ip_class(ip0):
    cl_A = 0
    cl_B = pow(2, 1)
    cl_C = pow(2, 1) + pow(2, 2)
    cl_D = pow(2, 1) + pow(2, 2) + pow(2, 3)
    cl_E = pow(2, 0) + pow(2, 1) + pow(2, 2) + pow(2, 3)
    numA = ip0 >> 7
    numB = ip0 >> 6
    numC = ip0 >> 5
    numD_E = ip0 >> 4
    if numA == cl_A:
        return "A"
    if numB == cl_B:
        return "B"
    if numC == cl_C:
        return "C"
    if numD_E == cl_D:
        return "D"
    if numD_E == cl_E:
        return "E"

def private_address(ip):
    ips = ip.split('.')
    if int(ips[0]) == 10 :
        return True
    elif int(ips[0]) == 192 and int(ips[1]) == 168 :
        return True
    elif int(ips[0]) == 172 and (int(ips[1]) >= 16 and int(ips[1]) <= 31):
        return True
    return False

def print_info(ind, ip_mask):
    if ind == 0:
        #aaa.aaa.aaa.aaa/aaa.aaa.aaa.aaa
        ip = ip_mask.split('/')[0]
        mask = ip_mask.split('/')[1]
        ip_cl = ip_class(int(ip.split('.')[0]))
        print ("ip : " + ip + " mask : " + mask)
        print ("class : " + ip_cl)
        private = private_address(ip)
        if private == True :
            print ("private : Yes")
        else :
            print ("private : No")
        mask_num = format_mask(mask)[1]
        num_of_subnets = pow(2, 32 - int(mask_num)) - 2
        print("subnets : " + str(num_of_subnets))
        ran = range_ips(ip, mask);
        network = '.'.join(ran[0])
        broadcast = '.'.join(ran[1])
        print("network : " + network)
        print("broadcast : " + broadcast)
    elif ind == 1:
        #aaa.aaa.aaa.aaa/aa
        ip = ip_mask.split('/')[0]
        mask = ip_mask.split('/')[1]
        ip_cl = ip_class(int(ip.split('.')[0]))
        print ("ip : " + ip + " mask : " + mask)
        print ("class : " + ip_cl)
        private = private_address(ip)
        if private == True :
            print ("private : Yes")
        else :
            print ("private : No")
        num_of_subnets = pow(2, 32 - int(mask)) - 2
        print("subnets : " + str(num_of_subnets))
        mask = cidr_to_mask(mask)
        mask = '.'.join(mask)
        print("mask : " + mask)
        ran = range_ips(ip, mask);
        network = '.'.join(ran[0])
        broadcast = '.'.join(ran[1])
        print("network : " + network)
        print("broadcast : " + broadcast)
    elif ind == 2:
        #aaa.aaa.aaa.aaa
        ip = ip_mask.split('/')[0]
        ip_cl = ip_class(int(ip.split('.')[0]))
        print ("ip : " + ip)
        private = private_address(ip)
        print ("class : " + ip_cl)
        if private == True :
            print ("private : Yes")
        else :
            print ("private : No")
    elif ind == 3:
        #/aaa.aaa.aaa.aaa
        mask = ip_mask.split('/')[1]
        mask_num = format_mask(mask)[1]
        print("mask : " + str(mask_num))
        num_of_subnets = pow(2, 32 - mask_num) - 2
        print("subnets : " + str(num_of_subnets))
    elif ind == 4:
        #/aa
        mask = ip_mask.split('/')[1]
        print("mask : " + str(mask))
        new_mask = cidr_to_mask(mask)
        new_mask = '.'.join(new_mask)
        print("mask : " + new_mask)
        num_of_subnets = pow(2, 32 - int(mask)) - 2
        print("subnets : " + str(num_of_subnets))

def range_ips(ip, mask):
    final_mask = ["255", "255", "255", "255"]
    ip = ip.split('.')
    mask = mask.split('.')
    mask_inverse = [0, 0, 0, 0]
    for i in range(0,4):
        mask_inverse[i] = ~(int(mask[i])) & 0xff
    first_ip = ["","","",""]
    final_ip = ["","","",""]
    for i in range(0,4):
        first_ip[i] = str((int(ip[i]) & int(mask[i])))
    for i in range(0, 4):
        final_ip[i] = str((int(ip[i]) | int(mask_inverse[i])))
    return [first_ip, final_ip]
def format_ip(addr):
    addr_nums = addr.split('.')
    for num in addr_nums:
        if int(num) < 0 or int(num) > 255:
            return False
    return True

def format_mask(addr):
    addr_nums = addr.split('.')
    result = 0
    if len(addr_nums) == 1:
        result = int(addr_nums[0])
        if int(addr_nums[0]) < 0 or int(addr_nums[0]) > 32:
            return False
    elif len(addr_nums) == 4:
        bit = 1
        zero_found = False
        for i in range(0, 4):
            shift = 7
            while shift != -1:
                found = bool((int(addr_nums[i]) >> shift) & bit)
                if found == True:
                    result = result + 1
                if zero_found == True and found == True:
                    return False
                if found == False :
                    zero_found = True
                shift = shift - 1
    return [True, result]

def check_format(addr):
    if addr[0] == '/' :
        mask = addr.split('/')
        return format_mask(mask[1])
    else :
        ip_mask = addr.split('/')
        if len(ip_mask) == 1 :
            if format_ip(ip_mask[0]) == False :
                return False
        elif len(ip_mask) == 2:
            if format_ip(ip_mask[0]) == False :
                return False
            mask = format_mask(ip_mask[1])
            if mask == False :
                return False
            mask = int(mask[1])
            #TODO(yassine): this is just default
            #if ip_class(int(ip_mask[0].split('.')[0])) == "A" and mask < 8:
                #return False
            #elif ip_class(int(ip_mask[0].split('.')[0])) == "B" and mask < 16:
                #return False
            #elif ip_class(int(ip_mask[0].split('.')[0])) == "C" and mask < 24:
                #return False
            #elif ip_class(int(ip_mask[0].split('.')[0])) == "D" and mask != 32:
                #return False
    return True

#int main(int argc, char **argv)
print ("exit || quit to exit the program, help to get help")
while True:
    string = input("ip : ")
    patterns = [ re.compile(r'\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/{1}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),#aaa.aaa.aaaa.aaa/aaa.aaa.aaa.aaa
                 re.compile(r'\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/{1}\d{1,2}'),#aaa.aaa.aaaa.aaa/aa
                 re.compile(r'\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),#aaa.aaa.aaaa.aaa
                 re.compile(r'\A/{1}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),#/aaa.aaa.aaa.aaa
                 re.compile(r'\A/{1}\d{1,2}')]#/aa
    string.lower()
    if string == "exit" or string == "quit" :
        break
    if string == "help" :
        print ("formats supported : \nxxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx")
        print ("xxx.xxx.xxx.xxx/xx")
        print ("xxx.xxx.xxx.xxx")
        print ("/xxx.xxx.xxx.xxx")
        print ("/xx")
        exec(open("ip-calc.py").read())
        break
    for i in range(0,5):
        result = patterns[i].findall(string)
        if bool(result):
            if i == 0:
                #format : aaa.aaa.aaa.aaa/aaa.aaa.aaa.aaa
                form = check_format(result[0])
                if form == False:
                    print("format error")
                else :
                    print_info(i, result[0])
                break;
            elif i == 1:
                #format : aaa.aaa.aaaa.aaa/aa
                form = check_format(result[0])
                if form == False:
                    print("format error")
                else :
                    print_info(i, result[0])
                break;
            elif i == 2:
                #format : aaa.aaa.aaaa.aaa
                form = check_format(result[0])
                if form == False:
                    print("format error")
                else :
                    print_info(i, result[0])
                break;
            elif i == 3:
                #format : /aaa.aaa.aaa.aaa
                form = check_format(result[0])
                if form == False:
                    print("format error")
                else :
                    print_info(i, result[0])
                break;
            elif i == 4:
                #format : /aa
                form = check_format(result[0])
                if form == False:
                    print("format error")
                else :
                    print_info(i, result[0])
                break;
        if len(result) == 0 and i == 4:
                print("format error")
