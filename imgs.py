import psycopg2
import socket
import requests
import random
import base64
import threading
from multiprocessing import Queue
import time

group = 1
thread_count = 250
conn_string = "host='' dbname='' user='postgres' password=''"


def stringscrub(data):
    data = data.replace("'", "''")
    return data

def checkIpv4(ip):
    reserved_addresses = [['10.0.0.0', '10.255.255.255'],
                          ['100.64.0.0', '100.127.255.255'],
                          ['127.0.0.0', '127.255.255.255'],
                          ['169.254.0.0', '169.254.255.255'],
                          ['172.16.0.0', '172.31.255.255'],
                          ['192.0.0.0', '192.0.0.255'],
                          ['192.0.2.0', '192.0.2.255'],
                          ['192.88.99.0', '192.88.99.255'],
                          ['192.168.0.0', '192.168.255.255'],
                          ['198.18.0.0', '198.19.255.255'],
                          ['198.51.100.0', '198.51.100.255'],
                          ['203.0.113.0', '203.0.113.255'],
                          ['224.0.0.0', '239.255.255.255'],
                          ['240.0.0.0', '.240.255.255.254'],
                          ['255.255.255.255', '255.255.255.255']]
    ip = ip.split(".")
    valid = True
    for a in range(0, len(reserved_addresses)):
        if ip[0] > reserved_addresses[a][0].split(".")[0] and ip[0] < reserved_addresses[a][1].split(".")[0]:
            valid = False
        if ip[1] > reserved_addresses[a][0].split(".")[1] and ip[1] < reserved_addresses[a][1].split(".")[1]:
            valid = False
        if ip[2] > reserved_addresses[a][0].split(".")[2] and ip[2] < reserved_addresses[a][1].split(".")[2]:
            valid = False
        if ip[3] > reserved_addresses[a][0].split(".")[3] and ip[3] < reserved_addresses[a][1].split(".")[3]:
            valid = False
    return valid


def scan(num, filters):
    netblock_check = False
    tblock = []
    while True:
        if netblock_check:
            if len(tblock) == 0:
                target = target.split(".")# this is set by this point
                for a in range(0, 255):
                    tblock += [str(target[0])+'.'+str(target[1])+'.'+str(target[2])+'.'+str(a)]
                    if a == 255:
                        netblock_check = False
            target = tblock[0]
            del tblock[0]
        else:
            if targets.qsize() > 0 and num % 2 == 1:
                target = targets.get()
            else:
                target = None
            if num % 2 == 1 or target == None:
                target = str(random.randint(1, 255)) + "." + str(random.randint(0, 255)) + "." + str(
                    random.randint(0, 255)) + "." + str(random.randint(0, 255))
                while checkIpv4(target) == False:
                    target = str(random.randint(1, 255)) + "." + str(random.randint(0, 255)) + "." + str(
                        random.randint(0, 255)) + "." + str(random.randint(0, 255))

        for a in range(0, len(filters)):
            if filters[a][4] == 'socket':
                # port check
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((target, filters[a][1]))
                if result == 0:
                    # open
                    try:
                        response = sock.recv(4096)
                        if filters[a][3] in str(response):
                            # conf string found
                            print("host: " + target + " filter: " + str(filters[a]) + " b64response: " + str(base64.b64encode(bytes(response))))
                            open("log.csv", "a").write(target+","+str(filters[a][0])+","+str(base64.b64encode(bytes(response)))+"\n")
                            netblock_check = True
                    except socket.error:
                        pass
            elif filters[a][4] == 'curl':
                # port check
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((target, filters[a][1]))
                if result == 0:
                    # open
                    try:
                        if filters[a][1] == 443 or filters[a][1] == 8443:
                            response = requests.get("https://" + target + ":" + str(filters[a][1]) + filters[a][2])
                        else:
                            response = requests.get("http://" + target + ":" + str(filters[a][1]) + filters[a][2])
                        if filters[a][3] in response.text:
                            # conf string found
                            print("host: " + target + " filter: " + str(filters[a]) + " b64response: " + str(base64.b64encode(bytes(response.text, 'utf-8'))))
                            open("log.csv", "a").write(target + "," + str(filters[a][0]) + "," + str(base64.b64encode(bytes(response.text, 'utf-8'))) + "\n")
                            netblock_check = True
                    except requests.exceptions.RequestException:
                        pass
            # port = filters[a][1]
            # file path filters[a][2]
            # confirmation string = filters[a][3]
            # type = filters[a][4]
            # type -> port -> file path if type curl -> confirmation string

def stats(timeout=60):
    while True:
        print("Next upload in " + str(timeout) + " seconds...")
        time.sleep(timeout)
        data = open("log.csv", "r").read().splitlines()
        conn = psycopg2.connect(conn_string)
        cursor = conn.cursor()
        for a in range(0, len(data)):
            query = "INSERT INTO targets (address, filter_id, scan_date, response) VALUES ('"+data[a].split(",")[0]+"', "+data[a].split(",")[1]+", CURRENT_TIMESTAMP, '"+stringscrub(data[a].split(",")[2])+"');"
            print(query)
            cursor.execute(query)
        open("log.csv", "w").write("")
        conn.commit()
        cursor.close()
        conn.close()


conn = psycopg2.connect(conn_string)
cursor = conn.cursor()
cursor.execute("SELECT * FROM filters WHERE filter_group_id = " + str(group) + ";")
filters = cursor.fetchall()
cursor.execute("SELECT * FROM filter_group JOIN filters ON filter_group.id = filters.filter_group_id JOIN targets ON targets.filter_id = filters.id WHERE filter_group.id = " + str(group) + " ORDER BY targets.scan_date DESC")
latest = cursor.fetchall()
targets = Queue(maxsize=0)
for a in range(0, len(latest)):
    targets.put(latest[a][10])
cursor.close()
conn.close()

t = threading.Thread(target=stats, args=(60,))
t.start()
for a in range(thread_count):
    t = threading.Thread(target=scan, args=(a, filters,))
    t.start()
