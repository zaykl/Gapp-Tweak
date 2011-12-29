# -*- coding=utf-8 -*-

""" 
    代理服务server端                                                                       
    Author : Kk
"""

import tornado.web
import tornado.httpserver
from tornado import httpclient

import urlparse
import logging
import pickle
import urllib2
import time
from httplib import responses

import settings
from async import uploadclient

# force system not use any proxy
proxy_handler = urllib2.ProxyHandler({})
opener = urllib2.build_opener(proxy_handler)
urllib2.install_opener(opener)

# following line can be comment in production env
logging.basicConfig(level=logging.INFO)

HTTP_STATUS_MESSAGES = responses

@settings.urlmap("/fetch.py")
class MainHandler(tornado.web.RequestHandler):
    Server = 'Router/0.1'
    
    def report(self, status, description):
        # header
        self.set_header(status, description)
        self.set_header(u'Content-Type', u'text/html')
        self.set_header(u'Coding', u'plain')
        # body
        content = u'<h1>Router Error</h1><p>Error Code: %s<p>Message: %s'\
                % (status, description)
        self.write(content)
        
    def uc_param(self, param):
        """ 
            for header name
        """
        ucParam = ''
        for word in param.split('-'):
            ucParam += word.capitalize() + '-'
        return ucParam.rstrip('-')
    
    def encode(self, data, coding):
        if data == '': return data
        if coding == 'zlib' or coding == 'base64':
            return data.encode(coding)
        return data
    
    def decode(self, data, coding):
        if data == '': return data
        if coding == 'zlib' or coding == 'base64':
            return data.decode(coding)
        return data

    @tornado.web.asynchronous
    def post(self):
        try:
            # Get coding and decode(or unzip, or decrypt) incoming message
            large_file_flag = u'False'
            self.in_data_coding = self.request.headers.get('Coding').decode('utf-8')
            fileno = self.request.headers.get('File-No', '').decode('utf-8')
            # Load object to dictionary.
            inMessage = self.decode(self.request.body, self.in_data_coding)
            inMessageDict = pickle.loads(inMessage)
    
            # Get the method of incoming  message
            #methodDict = {'GET': 'GET', 'POST': 'POST', 'HEAD': 'HEAD'}
            #if inMessageDict['method'] not in methodDict:
            #    self.report(590, 'Unsupported method: %s' % inMessageDict['method'])
            #    return
            method = inMessageDict['method']
    
            # Get payload coding of incoming message
            self.inPayloadCoding = inMessageDict.get('payload_coding', 'base64')

            # Make base64 path from path string in the incoming message
            self.path = self.decode(inMessageDict['path'], self.inPayloadCoding)
            #(scm, netloc, path, params, query, _) = urlparse.urlparse(self.path)
            #if (scm.lower() != 'http' and scm.lower() != 'https') or not netloc:
            #    self.report(590, 'Unsupported scheme: %s' % scm.lower())
            #    return
            #self.path = urlparse.urlunparse((scm, netloc, path, params, query, ''))

            # Make headers from the 'header' argument of incoming message
            headers = {}
            payload = None
            for name, value in inMessageDict['headers'].items():
                # Skip hop to hop headers
                #if name.lower() in self.SkipHeaders: continue
                if name.lower() == "large-file": 
                    large_file_flag = value
                    continue
                # Check postdata lenth of incoming message
                elif name.lower() == 'content-length':
                    payload = self.decode(inMessageDict['payload'], self.inPayloadCoding)
                    if int(value) != len(payload):
                        logging.info("Wrong length of postdata %d" %(len(payload))) 
                headers[self.uc_param(name)] = value
            headers['Connection'] = 'close'
            
            if payload != None and method != 'POST':
                self.report(u"590", u"Error http method. Payload without POST.")
                self.finish()
                return
            
        except Exception, e:
            self.report(u"591", u'Unkown error, %s.' % str(e))
            self.finish()
            return
        
        # Send request data 
        self.req_data = {
                    "headers":headers,
                    "method": method,
                    "body": payload, 
                    "follow_redirects":False,
                    "validate_cert":False,
                    "use_gzip":False,
                    "connect_timeout":30, 
                    "request_timeout":30,
                   }
        
        self.http = uploadclient.AsyncHTTPClient(max_clients=150)
        if fileno and self.path in self.http.keep_alive:
            fileno, length = fileno.split(":", 1)
            conn = self.http.keep_alive[self.path]
            self.http.keep_alive[self.path] = conn[0], length

        self.http.fetch(self.path, callback=self.on_response, **self.req_data)
        logging.info("Start fetching data") 


    def handle_error(self, resp, fileno=u'', length=u''):
       # 文件过大使用分块下载处理
        status = u""
        message = u""

        if resp.code == 592:
            logging.info('enable range support')
            self.set_header(u"592", fileno+':'+length)
            return self.handle_resp(resp)

        elif resp.code == 594:
            status = u"594"
            message = u'download large file completed'
        
        # 文件过大使用分块上传处理
        elif resp.code == 593:
            status = u"593"
            message = fileno+':'+length

        #elif resp.code == 599:
        #    status = u"591"
        #    message = resp.error.message
        else: 
            status = u"591"
            message = resp.error.message
        
        logging.info(message)
        self.report(status, message)
        self.finish()
        return
        
    def on_response(self, resp, fileno=u'', length=u''):
        """
            回调处理
        """
        # handle error response
        if resp.error: 
            if resp.code in (591, 592, 593, 594): 
                return self.handle_error(resp, fileno=fileno, length=length)
                
            elif resp.code == 599:
                # 599未知错误使用urllib2重试,此处造成拥塞 
                req = urllib2.Request(self.path,
                                    data=self.req_data['body'],
                                    headers=self.req_data['headers'])
                try:
                    del resp
                    resp = urllib2.urlopen(req, timeout=5)
                    resp.body = resp.read()
                
                except urllib2.HTTPError, e:
                    resp = e
                    resp.body = resp.read()
                    
                except urllib2.URLError,e:
                    logging.info(str(e))
                    self.report(u"591", str(e))
                    self.finish()
                    return

            else : 
                pass
        
        return self.handle_resp(resp)

    def handle_resp(self, resp):
        # coding info
        out_data_coding = self.in_data_coding
        outPayloadCoding = self.inPayloadCoding

        # HTTP status
        outStatus = resp.code
        outStatusMsg = HTTP_STATUS_MESSAGES.get(int(outStatus), 'ok')

        # HTTP headers
        outHeaders = {}
        if resp.headers:
            for header in resp.headers:
                if header.lower() == 'set-cookie':
                    scs = resp.headers[header]
                    logging.info('%s: %s' % (header, scs.strip()))
                    outHeaders[header] = scs
                    continue
                # Other headers
                outHeaders[header] = resp.headers[header]

        # Response raw data enbedded in payload
        data = resp.body
        outPayload = self.encode(data, outPayloadCoding)

        # Dump dictionary to Pickle object string
        message = pickle.dumps({'status': outStatus,
                              'status_msg': outStatusMsg,
                              'headers': outHeaders,
                              'payload_coding': outPayloadCoding,
                              'payload': outPayload,
                                })
        message = self.encode(message, out_data_coding)

        # Forward the outgoing Message back to the request router
        self.set_header(u'Content-Type', u'application/octet-stream')
        self.set_header(u'Version' , u'0.1')
        self.set_header(u'Coding' , out_data_coding)
        self.write(message)
        self.finish() 
        return 

    def get(self):
        self.write('ok') 


#@settings.urlmap("/upload")
#class Upload(tornado.web.RequestHandler): 
#    """
#      # Test upload
#    """
#    def get(self):
#        self.set_header(u"Content-Type", u"text/html; charset=utf-8")
#        self.write("""<html><head></head><body>
# <form method="POST" enctype="multipart/form-data" action="">
# <input type="file" name="myfile" />
# <br/>
# <input type="submit" />
# </form>
# </body></html>""")
#
#    def post(self):
#        if self.request.files:
#            for f in self.request.files['myfile']:
#                tf = open(f["filename"], 'wb')
#                tf.write(f["body"])  
#                tf.close()  
#        return self.redirect('/upload')
        
        
def main():
    """
        供测试使用
    """
    application = tornado.web.Application(settings.URLMAP)
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(settings.PORT)
    print "Server: http://%s:%d/" %(settings.SERVERIP, settings.PORT)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()
