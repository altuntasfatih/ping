
import time
import socket
import struct
import random
import argparse
import sys
from netaddr import *


description = """
    Rangerping is ping implemations
    Usage: python rangerping.py --target <domain> [ Options ...]
    Options are not mandatory
"""

parser = argparse.ArgumentParser("Echo Request ICMP==Ping", description)
parser.add_argument("--target", "-t", help="target Host", required=True)
parser.add_argument("--wait", "-w", help="timeout  for waiting respose,Default 2 seconds", required=False,default=2)
parser.add_argument("--message", "-m", help="message in echo Request,default:rangers lead the way", required=False,default='rangers lead the way')
parser.add_argument("--repetiton", "-r", help="Number of repetitions,default=3 ", required=False,default=3)
args = parser.parse_args()

ICMP_ECHO_REQUEST = 8


def checkSum(packet):
    # Bu kismi netten aldim,checksum ne icin kullanildigi ,ve ne ise yaradigini  ve nasil hesaplandigi ogrendim,eger  vaktim kalirsa  kendim komple yazacam burayi

    sum = 0
    count_to = (len(packet) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(packet[count + 1]) * 256 + ord(packet[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(packet):
        sum = sum + ord(packet[len(packet) - 1])
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer



def generateIcmpPacket(id ,message ,sequence):


    """
    type 8->echo request,code ->0

    struct is equilivent  C language  struct
    ->Checksum is very important,if it not  match other fields which used calculating checksum value,host don't responds,I have tried
        ->Host dont' respond
        ->  in the below slide,there is good source to understand icmp and checksum and how to calculate
            https://www.scribd.com/doc/7074846/ICMP-and-Checksum-Calc

      0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type(8)   |     Code(0)   |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Payload                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



   :
    """

    # packet = struct.pack('bbHHhs', 8, 0, 0, id, sequence,message)
    packet = struct.pack('bbHHh', 8, 0, 0, id, sequence)

    my_checksum = checkSum(packet +message)

    # socket.htons ->Byte Ordering
    packet = struct.pack('bbHHh', 8, 0 ,socket.htons(my_checksum), id, sequence)
    return packet+ message;


def generateHostList():
    print ("Create List")


def send_ping(args,target,increment):
    """
    addres family->socket.AF_INET(ipv4)
    protocol->socket.getprotobyname("icmp")
    Raw socket->In more simple terms its for adding custom headers instead of headers provided by the underlying operating system.

    """
    icmpsocket = None
    try:
        icmpsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error, msg:
        print 'Error : ' + str(msg[1])
        exit()

    host = None
    try:
        host = socket.gethostbyname(target)
    except Exception, e:
        print 'Erorr host: ' + str(e)
        exit()

    id = int((time.time() * random.random()) % 65535)  # because id field lenght is 16 bit
    print "Sended to "+ host+   " id="+str(id)+" seqnum= "+str(42+increment)
    packet = generateIcmpPacket(id, args.message, 42+increment)

    while True:
        sent = icmpsocket.sendto(packet, (host, 42))  # There is no port for icmp message ,therefore we check incoming message id with our's sent id
        if (sent != 0):
            break;

    value = get_response(icmpsocket, id, time.time(), args)
    if(value==-1):
        print "Timeout to from "+host
    icmpsocket.close()



def get_response(icmpsocket, packet_id, timeofsent, args):
    icmpsocket.settimeout(float(args.wait))

    try:
        while True:
            timeofreceive = time.time()
            response, addr = icmpsocket.recvfrom(1024)
            header = response[20:28]
            type, code, checksum, id, sequence = struct.unpack('bbHHh', header)
            #print "Reply from "+str(addr[0]) +"  "+str(type)+"  "+ str(code)  +" " + str(checksum) + " "+"id= " + str(id) +  " ","seq=:"+str(sequence) +" len(response)"+ str(len(response))+ "in bytes"

            if id == packet_id:
                difference=timeofreceive - timeofsent
                print "Reply from " + str(addr[0]) + " " +\
                    "id= " +str(id) + " "+\
                    "seq= " + str( sequence) +" "+\
                    "Response " +str(len(response)) +" in bytes" +" "+ \
                    "message:" + response[ 28:]+" "+ \
                    "time= " + str(round( difference*1000.0, 4)) +" milliseconds"

                return 0

    except socket.timeout as errr:
        return -1


if __name__ == '__main__':
    # Testing
    if len(sys.argv) < 2:
        print parser.print_help()
        exit()
    repetation=int(args.repetiton)

    if ("/" in args.target):  # subnet

        for ip in IPSet([args.target]):
            for i in range(0, repetation):

                send_ping(args,str(ip),i)

    else:
        for i in range(0,repetation):
            send_ping(args,args.target,i)







