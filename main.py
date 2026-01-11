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
# -*- coding: utf-8 -*-

import threading
import time
import sys
import os
import socketserver

# 添加项目路径
sys.path.append(os.path.dirname(__file__))

"""def start_packet_capture():
    启动NetFlow数据收集（使用您的collector_v9.py）
    try:
        from data_collection.netflow_server import start_netflow_server
        print("启动NetFlow收集器...")
        start_netflow_server()
    except Exception as e:
        print(f"启动NetFlow收集器失败: {e}")"""
def start_packet_capture():
    """启动NetFlow数据收集 - 处理真实NetFlow数据"""
    try:
        # 直接使用您的collector_v9.py处理NetFlow
        from data_collection.collector_v9 import createdb
        import socketserver
        print("初始化数据库...")
        createdb()  # 创建netflow表
        
        print("启动NetFlow收集器，监听端口 9995...")
        
        # 使用collector_v9.py的NetFlow处理逻辑
        from data_collection.collector_v9 import ExportPacket,TemplateFlowSet
        
        class NetFlowUDPHandler(socketserver.BaseRequestHandler):
            TEMPLATES = {}
            
            def handle(self):
                data = self.request[0]
                host = self.client_address[0]
                
                try:
                    # 使用您现有的NetFlow解析逻辑
                    export = ExportPacket(data, self.TEMPLATES)
                    self.TEMPLATES.update(export.templates)
                    
                    # 流数据会自动存储到netflow.db（通过collector_v9.py的代码）
                    if hasattr(export, 'flows') and export.flows:
                        print(f"📥 收到来自 {host} 的NetFlow数据，处理了 {len(export.flows)} 个流")
                    else:
                        print(f"📥 收到来自 {host} 的NetFlow数据包，长度: {len(data)} 字节")
                        
                except Exception as e:
                    print(f"处理NetFlow数据失败: {e}")
        
        server = socketserver.UDPServer(("0.0.0.0", 9995), NetFlowUDPHandler)
        server.serve_forever()
        
    except Exception as e:
        print(f"启动NetFlow收集器失败: {e}")

def start_anomaly_detection():
    """启动异常检测（来自ai-network-anomaly）
    from anomaly_detection.simple_detector import start_detection_service
    print("启动异常检测...")
    start_detection_service()"""

    """启动数据处理和异常检测"""
    try:
        from data_integration.flow_processor import FlowProcessor
        
        print("启动数据处理器...")
        processor = FlowProcessor()
        processor.start_processing()
        
    except Exception as e:
        print(f"启动数据处理器失败: {e}")

def start_simple_monitor():
    """简单的监控显示"""
    try:
        from config import DATABASE_PATH, MONITOR_INTERVAL
        import sqlite3
        
        print("启动监控显示...")
        
        while True:
            try:
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                
                # 检查表是否存在
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='netflow'
                """)
                flow_table_exists = cursor.fetchone()
                
                if flow_table_exists:
                    cursor.execute("SELECT COUNT(*) FROM netflow")
                    total_flows = cursor.fetchone()[0]
                else:
                    total_flows = 0
                
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='anomaly_records'
                """)
                anomaly_table_exists = cursor.fetchone()
                
                if anomaly_table_exists:
                    cursor.execute("SELECT COUNT(*) FROM anomaly_records")
                    total_anomalies = cursor.fetchone()[0]
                else:
                    total_anomalies = 0
                
                print(f"📊 流记录总数: {total_flows} | ⚠️  异常记录: {total_anomalies}")
                
                conn.close()
                
            except Exception as e:
                print(f"监控出错: {e}")
            
            time.sleep(MONITOR_INTERVAL)
                
    except Exception as e:
        print(f"启动监控失败: {e}")

def start_web_interface():
    """暂时跳过Web界面"""
    print("Web interface skipped for now")
    pass
    """启动Web界面（来自mnet）"""
    '''  os.chdir('web_interface')
    import subprocess
    print("启动Web界面...")
    subprocess.run(['python', 'manage.py', 'runserver', '0.0.0.0:8000'])'''

def main():
    """主函数"""
    print("启动网络流量分析系统...")
    print("=" * 50)
    
    # 创建线程
    threads = []
    # 数据包捕获线程
    capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
    threads.append(capture_thread)
    
    # 异常检测线程  
    detection_thread = threading.Thread(target=start_anomaly_detection, daemon=True)
    threads.append(detection_thread)
    
    # 监控显示线程
    monitor_thread = threading.Thread(target=start_simple_monitor, daemon=True)
    threads.append(monitor_thread)

    # Web界面线程
    web_thread = threading.Thread(target=start_web_interface, daemon=True)
    threads.append(web_thread)
    
    # 启动所有线程
    for thread in threads:
        thread.start()
        time.sleep(1)
    
    print("所有服务已启动！")
    print("NetFlow服务器监听端口: 9995")
    'print("Web界面: http://localhost:8000")'
    print("监控显示: 每30秒更新统计")
    print("按 Ctrl+C 退出")
    print("=" * 50)

    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("正在关闭系统...")

if __name__ == "__main__":
    main()