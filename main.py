'''# -*- coding=utf-8 -*-


import logging
import sys
import socketserver
from collector_v9 import ExportPacket, createdb

logging.getLogger().setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)


class SoftflowUDPHandler(socketserver.BaseRequestHandler):

    TEMPLATES = {}

    @classmethod
    def get_server(cls, host, port):
        logging.info("Listening on interface {}:{}".format(host, port))
        server = socketserver.UDPServer((host, port), cls)
        return server

    def handle(self):
        data = self.request[0]
        host = self.client_address[0]
        s = "Received data from {}, length {}".format(host, len(data))
        logging.debug(s)
        # 使用类ExportPacket处理数据,并返回实例export,这是整个处理的开始!
        export = ExportPacket(data, self.TEMPLATES)
        # 把实例export(类ExportPacket)中的属性templates更新到类SoftflowUDPHandler的属性templates,用于保存模板数据
        self.TEMPLATES.update(export.templates)
        s = "Processed ExportPacket with {} flows.".format(export.header.count)
        logging.debug(s)


if __name__ == "__main__":
    createdb()
    server = SoftflowUDPHandler.get_server('0.0.0.0', 9995)

    logging.getLogger().setLevel(logging.DEBUG)

    try:
        logging.debug("Starting the NetFlow listener")
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        raise
'''

#!/usr/bin/env python3
"""
主启动文件 - 整合三个项目的功能
"""
import threading
import time
import sys
import os

# 添加项目路径
sys.path.append(os.path.dirname(__file__))

def start_packet_capture():
    """启动数据包捕获（来自packet_analysis）"""
    from data_collection.packet_capture import start_capture
    print("启动数据包捕获...")
    start_capture()

def start_anomaly_detection():
    """启动异常检测（来自ai-network-anomaly）"""
    from anomaly_detection.simple_detector import start_detection_service
    print("启动异常检测...")
    start_detection_service()

def start_web_interface():
    """启动Web界面（来自mnet）"""
    os.chdir('web_interface')
    import subprocess
    print("启动Web界面...")
    subprocess.run(['python', 'manage.py', 'runserver', '0.0.0.0:8000'])

def main():
    """主函数"""
    print("启动网络流量分析系统...")
    
    # 创建线程
    threads = []
    # 数据包捕获线程
    capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
    threads.append(capture_thread)
    
    # 异常检测线程  
    detection_thread = threading.Thread(target=start_anomaly_detection, daemon=True)
    threads.append(detection_thread)
    
    # Web界面线程
    web_thread = threading.Thread(target=start_web_interface, daemon=True)
    threads.append(web_thread)
    
    # 启动所有线程
    for thread in threads:
        thread.start()
    
    print("所有服务已启动！")
    print("Web界面: http://localhost:8000")
    print("按 Ctrl+C 退出")
    
    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("正在关闭系统...")

if __name__ == "__main__":
    main()