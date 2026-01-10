
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
import threading
from scapy.all import sniff, IP, TCP, UDP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def packet_handler(packet):
    """处理数据包的简单函数"""
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            print(f"捕获到数据包: {src_ip} -> {dst_ip}, 协议: {protocol}")
            
            # 这里可以添加数据存储逻辑
            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'timestamp': time.time()
            }
    except Exception as e:
        logger.error(f"处理数据包出错: {e}")

def start_capture(interface="eth0", packet_count=0):
    """开始捕获数据包"""
    logger.info(f"开始在接口 {interface} 上捕获数据包...")
    
    try:
        # 捕获数据包，packet_count=0 表示无限捕获
        sniff(iface=interface, prn=packet_handler, count=packet_count)
    except Exception as e:
        logger.error(f"捕获数据包失败: {e}")
        logger.info("尝试以管理员权限运行或检查网络接口名称")

def start_capture_service():
    """启动捕获服务（供main.py调用）"""
    start_capture()

if __name__ == "__main__":
    start_capture_service()