#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import signal
import socket
import select
import SocketServer
import struct
import string
import hashlib
import sys
import os
import json
import logging
import getopt
import httplib
import urlparse
import pickle

def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table


fetchserver = "http://127.0.0.1:7777/newfetch.py"

class HttpClient():
    """
    """
    def __init__(self, fetchserver):
        (scm, netloc, path, params, query, _) = urlparse.urlparse(fetchserver)
        self.path = path
        self.con = httplib.HTTPConnection(netloc)
    
    def send(self, body):
        headers = {} 
        headers['Connection'] = 'Keep-Alive'
        headers['Content-Type'] ='application/octet-stream'
        self.con.request("POST", self.path, body, headers)
        
    def read(self):
        resp = self.con.getresponse()         
        resp.body = resp.read()
        return resp.body


    def close(self):
        self.con.close()


class GetRouter():
    ''' Get router. Enable load balance when multiple routers are used. '''
    i=0
    def __call__(self):
        if len(common.fetchServers) == 0:
            common.fetchServers = common.backupServers
        self.i = (self.i+1) % len(common.fetchServers)
        return str(common.fetchServers[self.i])

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, fileno):
        try:
            blockSize = 4096
            fdset = [sock]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    complete = False
                    recv = sock.recv(blockSize)

                    if len(recv) <= 0:break

                    while recv:
                        fetch = HttpClient(fetchserver)        
                        message = pickle.dumps({
                        'recv': recv,
                        'fileno':fileno
                        })
                        fetch.send(message)

                        if len(recv) < blockSize:
                            complete = True
                            break
                        else:
                            recv = sock.recv(blockSize)

                    isDone = False
                    while complete:
                        fetch = HttpClient(fetchserver)        
                        message = pickle.dumps({
                          'resp':'1',
                          'fileno':fileno
                        })
                        fetch.send(message)
                        resp = fetch.read()
                        resp = pickle.loads(resp)
                        isDone = resp['isDone']
                        resp = resp['resp']
                        if resp:
                            sock.send(resp)
                        else:
                            break

                        if isDone:
                            break 

                #if remote in r:
                #    if sock.send(self.decrypt(remote.recv(4096))) <= 0:
                #        break
        finally:
            sock.close()

    def encrypt(self, data):
        print "\n-------send------------\n"
        print data
        print "\n-------send------------\n"
        return data
        return data.translate(encrypt_table)

    def decrypt(self, data):
        print "\n-------rev------------\n"
        print data
        print "\n-------rev------------\n"
        return data
        return data.translate(decrypt_table)

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        try:
            sock = self.connection
            sock.recv(262)
            sock.send("\x05\x00")
            data = self.rfile.read(4)
            mode = ord(data[1])
            if mode != 1:
                logging.warn('mode != 1')
                return
            addrtype = ord(data[3])
            addr_to_send = data[3]
            if addrtype == 1:
                addr_ip = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:
                addr_len = sock.recv(1)
                addr = self.rfile.read(ord(addr_len))
                addr_to_send += addr_len + addr
            else:
                logging.warn('addr_type not support')
                # not support
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port
            port = struct.unpack('>H', addr_port)
            try:
                reply = "\x05\x00\x00\x01"
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)
                sock.send(reply)
                # reply immediately
                if '-6' in sys.argv[1:]:
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                fetch = HttpClient(fetchserver)        

                message = pickle.dumps({
                          'path': addr_to_send,
                          })

                fetch.send(message)
                fileno = fetch.read()
                #remote.connect((addr, port[0]))
                #remote.connect((SERVER, REMOTE_PORT))
                #self.send_encrypt(remote, addr_to_send)
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_tcp(sock, fileno)
        except socket.error, e:
            logging.warn(e)

def exit(sig, frame):
    import os
    os._exit(0)

if __name__ == '__main__':

    signal.signal(signal.SIGCHLD,signal.SIG_IGN)
    signal.signal(signal.SIGINT, exit)

    os.chdir(os.path.dirname(__file__) or '.')

    with open('config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:l:')
    for key, value in optlist:
        if key == '-p':
            REMOTE_PORT = int(value)
        elif key == '-k':
            KEY = value
        elif key == '-l':
            PORT = int(value)
        elif key == '-s':
            SERVER = value

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    encrypt_table = ''.join(get_table(KEY))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        #server.allow_reuse_address = True
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)

