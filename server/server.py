# -*- coding=utf-8 -*-

"""
    主程序入口
    
    Author : zay
    Email  : kill84144159@hotmail.com
    
"""
import os.path
import tornado.httpserver
import tornado.ioloop
import tornado.web
import fetch
import settings

def main():
    """
        主程序入口
    """
    application = tornado.web.Application(settings.URLMAP)
    http_server = tornado.httpserver.HTTPServer(application)
    #http_server.listen(settings.PORT)
    http_server.bind(settings.PORT)
    http_server.start(0)
    print "Server: http://%s:%d/" %(settings.SERVERIP, settings.PORT)
    tornado.ioloop.IOLoop.instance().start()
    
if __name__ == "__main__":
    main()
