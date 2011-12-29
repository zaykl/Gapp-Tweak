# -*- coding=utf-8 -*-

"""         
    Description:代理服务client端    
    
    Author : Kk
    Email  : liangkazhe@gmail.com
"""


import BaseHTTPServer
import SocketServer
import httplib
import urlparse
import socket
import re
import pickle
try:
    import ssl
    SSLEnable = True
except:
    SSLEnable = False
import logging

import common

if common.DEBUG:
    logging.basicConfig(level=logging.INFO)

# force system not use any proxy
#proxy_handler = urllib2.ProxyHandler({})
#opener = urllib2.build_opener(proxy_handler)
#urllib2.install_opener(opener)


class HttpClient():
    """
    """
    def __init__(self, fetchserver):
        (scm, netloc, path, params, query, _) = urlparse.urlparse(fetchserver)
        self.path = path
        self.con = httplib.HTTPConnection(netloc)
    
    def send(self, body, headers):
        self.con.request("POST", self.path, body, headers)
        
        resp = self.con.getresponse()         
        headers = {}
        for i in resp.getheaders():
            name = uc_param(i[0])
            headers[name] = i[1]
        resp.headers = headers
        resp.body = resp.read()
        return resp
        
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

def encode(data, coding):
    """
        数据加密
    """
    if data == '':  return data;
    if coding == 'zlib' or coding == 'compress':
        return data.encode('zlib')
    elif coding == 'base64':
        return data.encode('base64')
    return data


def decode(data, coding):
    """
        数据解密
    """
    if data == '':  return data
    if coding == 'zlib' or coding == 'compress':
        return data.decode('zlib')
    elif coding == 'base64':
        return data.decode('base64')
    return data


def uc_param(param):
    """ 
        for header name
    """
    ucParam = ''
    for word in param.split('-'):
        ucParam += word.capitalize() + '-'
    return ucParam.rstrip('-')


class LocalProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
        本地代理服务器
    """
    # Config
    get_router = GetRouter();
    data_limit = 0x100000
    # 上传和url加密格式
    payload_coding='base64'
    # 整个http消息加密格式
    data_coding='zlib'

        
    def hide_log_message(self, format, *args):
        pass


    def do_CONNECT(self):
        """
            hack for support https，do not update do_CONNECT method
        """
        if not SSLEnable:
            self.send_error(501, 'Local proxy error, HTTPS needs Python2.6 or later.')
            self.connection.close()
            return

        # for ssl proxy
        (httpsHost, _, httpsPort) = self.path.partition(':')
        
        # continue
        self.wfile.write('HTTP/1.1 200 OK\r\n')
        self.wfile.write('\r\n')
        try:
            sslSock = ssl.SSLSocket(self.connection,
                                      server_side=True,
                                      certfile=common.DEF_CERT_FILE,
                                      keyfile=common.DEF_KEY_FILE)
        except:
            return
        # rewrite request line, url to abs
        firstLine = ''
        while True:
            chr = sslSock.read(1)
            # EOF?
            if chr == '':
                # bad request
                sslSock.close()
                self.connection.close()
                return
            # newline(\r\n)?
            if chr == '\r':
                chr = sslSock.read(1)
                if chr == '\n':
                    # got
                    break
                else:
                    # bad request
                    sslSock.close()
                    self.connection.close()
                    return
            # newline(\n)?
            if chr == '\n':
                # got
                break
            firstLine += chr

        # get path
        (method, path, ver) = firstLine.split()
        if path.startswith('/'):
            path = 'https://%s' % httpsHost + path

        # connect to local proxy server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', common.DEF_LISTEN_PORT))
        sock.send('%s %s %s\r\n' % (method, path, ver))

        # forward https request
        sslSock.settimeout(1)
        while True:
            try:
                data = sslSock.read(8192)
            except ssl.SSLError, e:
                if str(e).lower().find('timed out') == -1:
                    # error
                    sslSock.close()
                    self.connection.close()
                    sock.close()
                    return
                # timeout
                break
            if data != '':
                sock.send(data)
            else:
                # EOF
                break
        sslSock.setblocking(True)

        # simply forward response
        while True:
            data = sock.recv(8192)
            if data != '':
                try:
                    sslSock.write(data)
                except :
                    return
            else:
                # EOF
                break

        # clean
        sock.close()
        sslSock.shutdown(socket.SHUT_WR)
        sslSock.close()
        self.connection.close()


    def build_request(self, payload, path=None, fileno='', fetchserver=None):
        # Make headers for pickle or json
        headers = {}
        for key in self.headers:
            headers[key]= self.headers[key]
            
        # Encoding payload binary data to a string
        payload = encode(payload, self.payload_coding)
        message = pickle.dumps({'method': self.command,
                          'path': encode(path, self.payload_coding),
                          'headers': headers,
                          'payload_coding': self.payload_coding,
                          'payload': payload,})
        # zlib加密打包数据
        data = encode(message, self.data_coding)
            
        fetch_server = fetchserver or self.get_router()
        fetch_headers = {}
        fetch_headers['Accept-Encoding'] = 'identity, *;q=0'
        fetch_headers['Connection'] = 'Keep-Alive'
        fetch_headers['Content-Type'] ='application/octet-stream'
        fetch_headers['Coding'] = self.data_coding
        fetch_headers['File-No'] = fileno
        return data, fetch_headers, fetch_server

        
    def do_METHOD(self):
        # check http method and post data
        methodList = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE']
        if self.command not in methodList:
            self.report(501, 'Unsupported HTTP method.')
            return
        payloadLen = 0
        if self.command == 'POST':
            if self.headers.has_key('Content-Length'):
                payloadLen = int(self.headers['Content-Length'])

        # do path check
        (scm, netloc, path, params, query, _) = urlparse.urlparse(self.path)

        if (scm.lower() != 'http' and scm.lower() != 'https') or not netloc:
            self.send_error(501, 'Local proxy error, Unsupported scheme(ftp for example).')
            self.connection.close()
            return
        path = urlparse.urlunparse((scm, netloc, path, params, query, ''))

        # get post data
        payload = ''
        if payloadLen < self.data_limit:
            payload = self.rfile.read(payloadLen)
            if len(payload) != payloadLen:
                logging.info("Payload lengh not correct!")
     
            data, headers, fetch_server = self.build_request(payload, path=path)

            try:
                fetch = HttpClient(fetch_server)
                resp = fetch.send(data, headers)
                #resp = urllib2.urlopen(request, data)
            except Exception, e:
                logging.info(str(e))
                self.connection.close()
                return 
            
            if "592" in resp.headers and self.command in ('GET', 'POST'):
                self.process_large_resp(path, 
                                        fetch,
                                        resp.headers["592"],
                                        resp
                                        )
                fetch.close()
            else:
                self.processData(resp)
            
        else:
            # 分块处理大文件上传
            self.processLargeRequest(path, payloadLen)    

        self.connection.close()
        return


    def processData(self, resp):
        """
            解析处理从fetch server返回的请求
        """
        # 正常输出结果
        if 'Version' in resp.headers:
            Version = resp.headers['Version']
            Coding = 'plain'
            if Version == '0.1':
                Coding = resp.headers['Coding']
                message = decode(resp.body, Coding)
            else:
                self.report(591, 'Unkown version , check your router.')
                return
            messageDict = pickle.loads(message)

            status = int(messageDict["status"])
            # 将592状态转成200
            if status in set([592]): status = 200
            try:
                self.send_response(status, messageDict['status_msg'])
            except Exception, e:
                logging.info(str(e))
            #headers = messageDict['headers'].split('\r\n')
            headers = messageDict['headers']

            # for headers
            try:
                for header,value in headers.items():
                    # Skip headers for Dev team
                    if header.lower() in common.SKIP_HEADERS:
                        continue
                    elif header.lower() == 'set-cookie':
                    # handle long cookies
                        scs = value.split(',')
                        nsc = ''
                        for sc in scs:
                            if nsc == "":
                                nsc = sc
                            elif re.match(r'[ \t]*[0-9]', sc):
                                # expires 2nd part
                                nsc += "," + sc
                            else:
                                self.send_header(header, nsc.strip())
                                nsc = sc
                        self.send_header(header, nsc.strip())
                        continue
                    #elif header.lower() == 'content-encoding':
                    #    continue
                    self.send_header(header, value)
            except Exception, e: 
                logging.info(str(e))
            self.end_headers()
            # The page
            payload_coding = messageDict['payload_coding']
            payload = decode(messageDict['payload'], payload_coding)
            try:
                self.wfile.write(payload)
            except Exception, e:
                logging.info(str(e))

        # 输出错误信息
        else :
            try:
                self.send_response(200, 'OK')
                # The headers
                for key in resp.headers.items():
                    self.send_header(key, resp.headers[key])
                self.end_headers()
                # The page
                self.wfile.write(resp.read())
            except Exception, e:
                logging.info(str(e))
        

        
    def processLargeRequest(self, path, contentLength):
        """
            分段上传大文件
        """
        # 0x100000  1m initial, at least 64k
        partLength = self.data_limit
        body_left = contentLength
        fetchserver = self.get_router()
        fetch = HttpClient(fetchserver)

        payload = self.rfile.read(partLength)  
        body_left -= partLength
        fileno = ''
        while payload:
            self.headers['Large-File'] = str(contentLength)
            data, headers, _ignore = self.build_request(payload, 
                                                        path=path, 
                                                        fileno=fileno,
                                                        )

            try:
                logging.info("Upload pieces!")
                resp = fetch.send(data, headers)       
                #resp = urllib2.urlopen(request, data)
            except Exception, e:
                logging.info(str(e))
                resp = e
            
            if "593" in resp.headers:
                fileno = resp.headers["593"]
                if body_left == 0:
                    break
                elif body_left >= partLength:
                    payload = self.rfile.read(partLength)
                    body_left -= partLength
                elif body_left < partLength:
                    payload = self.rfile.read(body_left)
                    body_left = 0
            else:
                break

        # 上传完毕后处理返回    
        self.processData(resp)   
            
    def process_large_resp(self, path, fetch, fileno, resp):
        """
            分段下载 
        """
        self.processData(resp)

        while True:

            data, headers, ignore = self.build_request("", 
                                                       path=path, 
                                                       fileno=fileno,
                                                       )
            logging.info("Download pieces!")
            resp = fetch.send(data, headers)
            #resp = urllib2.urlopen(request, data)

            if "594" in resp.headers:
                logging.info("Download completed!")
                break
            elif "592" in resp.headers:
                fileno = resp.headers["592"]
            try:
                # 处理返回    
                Coding = resp.headers['Coding']
                message = decode(resp.body, Coding)
                messageDict = pickle.loads(message)

                # The page
                payload_coding = messageDict['payload_coding']
                payload = decode(messageDict['payload'], payload_coding)
                self.wfile.write(payload)
            except Exception, e:
                logging.info(str(e))
                return
            
            
    if not common.DEBUG:
        log_message = hide_log_message    
    do_GET = do_METHOD
    do_HEAD = do_METHOD
    do_PUT = do_METHOD
    do_DELETE = do_METHOD
    do_POST = do_METHOD        
            
            
class ThreadingHTTPServer(SocketServer.ThreadingMixIn,
                          BaseHTTPServer.HTTPServer):
    pass

    
    
def start_service():
    """开启代理服务应用
    """
    print u'--------------------------------------------'
    print u'代理服务已开启'
    print u'HTTP Enabled : YES'
    if SSLEnable:
        print u'HTTPS Enabled: YES'
    else:
        print u'HTTPS Enabled: NO'
    print u'请修改浏览器代理为如下地址: %s:%d' % ('127.0.0.1',common.DEF_LISTEN_PORT)
    print '--------------------------------------------'
    httpd = ThreadingHTTPServer(('', common.DEF_LISTEN_PORT),
                                LocalProxyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    start_service()

