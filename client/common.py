# -*- coding=utf-8 -*-

"""
    客户端配置程序

    Author: kk
"""
import os,sys
import ConfigParser

DEBUG = False

def module_path():
    return os.path.dirname(__file__)

def get_config():
    """
        读取本地代理端口
    """
    init_conf = {}
    try:
        config = ConfigParser.ConfigParser()
        config.read(DEF_CONF_FILE)
        port = config.get("Config", "port")
        init_conf['port'] = int(port)
        init_conf['default_url'] = config.get("Config", "default_url")
        init_conf['fetch_server']  = eval(config.get("Config", "fetch_server"))
        init_conf['skip_headers'] = eval(config.get("Config", "skip_headers"))
    except:
        pass
    return init_conf
   

dir = module_path()

DEF_KEY_FILE  = os.path.join(dir, 'cert/ca.key')
DEF_CERT_FILE = os.path.join(dir, 'cert/ca.crt')
DEF_CONF_FILE = os.path.join(dir, 'config.ini')
CONFIG = get_config()


#本地监听端口
DEF_LISTEN_PORT= CONFIG.get('port', 8000)
SKIP_HEADERS = set(CONFIG.get('skip_headers', []))
fetchServers = CONFIG.get('fetch_server', [])
proxy_ip = "127.0.0.1" 

