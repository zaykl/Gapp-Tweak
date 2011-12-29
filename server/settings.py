#coding:utf-8
import socket
import struct

# 进行url mapping处理
URLMAP = []
def urlmap(url):
    def _(cls):
        URLMAP.append((url, cls))
        return cls
    return _

def get_ip_address(ifname):
    """
        描述: 获取ip地址
        使用: get_ip_address('eth0')
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

# 配置ifname获取外网ip地址
IFNAME = 'eth0'
# 设置服务器监听端口
PORT = 7777
# 服务器外网ip地址
try:
    import fcntl
    SERVERIP = get_ip_address(IFNAME)
except:
    SERVERIP = "127.0.0.1"

# 向主服务器报告状态
MAIN_SERVER = 'http://127.0.0.1:8888/report?server=http://%s:%d/fetch.py' \
                %(SERVERIP, PORT)
