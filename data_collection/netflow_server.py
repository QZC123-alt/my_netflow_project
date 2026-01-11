
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socketserver
import threading
import logging
import sys
import os

# 添加路径以导入您的collector_v9
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from collector_v9 import ExportPacket, createdb

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetFlowUDPHandler(socketserver.BaseRequestHandler):
    """
    基于您的collector_v9.py的UDP处理器
    """
    TEMPLATES = {}
    
    def handle(self):
        try:
            data = self.request[0]
            host = self.client_address[0]
            
            logger.info(f"收到来自 {host} 的NetFlow数据，长度: {len(data)} 字节")
            
            # 使用您的ExportPacket处理数据
            export = ExportPacket(data, self.TEMPLATES)
            self.TEMPLATES.update(export.templates)
            
            logger.info(f"处理了 {len(export.flows)} 个流记录")
            
            # 流数据已经在ExportPacket中自动存储到数据库了
            
        except Exception as e:
            logger.error(f"处理NetFlow数据出错: {e}")

def start_netflow_server():
    """启动NetFlow服务器"""
    try:
        # 创建数据库
        createdb()
        logger.info("数据库初始化完成")
        
        # 启动UDP服务器监听NetFlow数据
        server = socketserver.UDPServer(("0.0.0.0", 9995), NetFlowUDPHandler)
        logger.info("NetFlow服务器启动，监听端口 9995...")
        logger.info("等待Softflowd或NetFlow导出器发送数据...")
        
        server.serve_forever()
        
    except Exception as e:
        logger.error(f"启动NetFlow服务器失败: {e}")

if __name__ == "__main__":
    start_netflow_server()