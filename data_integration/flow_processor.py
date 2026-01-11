
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import time
import threading
import logging
import sys
import os

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from anomaly_detection.simple_detector import SimpleAnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FlowProcessor:
    """连接数据收集和异常检测的桥梁"""
    
    def __init__(self, db_path='flow.db'):
        self.db_path = db_path
        self.detector = SimpleAnomalyDetector()
        self.is_running = False
        self.check_interval = 5  # 每5秒检查一次新数据
        
    def get_new_flows(self):
        """从数据库获取最新的流记录"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 获取最近的流记录
            cursor.execute("""
                SELECT timestamp, in_bytes, out_bytes, protocol, in_pkts, out_pkts 
                FROM flow_data 
                WHERE timestamp > datetime('now', '-30 seconds')
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            
            flows = cursor.fetchall()
            conn.close()
            
            return flows
            
        except Exception as e:
            logger.error(f"获取流数据失败: {e}")
            return    
    def process_new_flows(self):
        """处理新的流数据"""
        flows = self.get_new_flows()
        
        if flows:
            logger.info(f"发现 {len(flows)} 条新的流记录")
            
            for flow in flows:
                # 转换为检测器需要的格式
                flow_data = {
                    'timestamp': flow[0],
                    'in_bytes': flow[1],
                    'out_bytes': flow[2], 
                    'protocol': flow[3],
                    'in_pkts': flow[4],
                    'out_pkts': flow[5]
                }
                
                # 进行异常检测
                result = self.detector.analyze_flow(flow_data)
                
                if result and result['is_anomaly']:
                    logger.warning(f"⚠️  发现异常流量! 分数: {result['score']:.2f}")
                    self.handle_anomaly(flow_data, result)
    
    def handle_anomaly(self, flow_data, result):
        """处理异常检测结果"""
        # 这里可以添加报警逻辑
        logger.warning(f"异常详情: {flow_data}")
        logger.warning(f"检测结果: {result}")
        
        # 存储异常记录（可选）
        self.save_anomaly_record(flow_data, result)
    
    def save_anomaly_record(self, flow_data, result):
        """保存异常记录到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 创建异常记录表（如果不存在）
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    flow_data TEXT,
                    anomaly_score REAL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # 插入异常记录
            cursor.execute("""
                INSERT INTO anomaly_records (timestamp, flow_data, anomaly_score)
                VALUES (?, ?, ?)
            """, (flow_data['timestamp'], str(flow_data), result['score']))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存异常记录失败: {e}")
    
    def start_processing(self):
        """开始处理循环"""
        self.is_running = True
        logger.info("开始流量数据处理...")
        
        while self.is_running:
            try:
                self.process_new_flows()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"处理循环出错: {e}")
                time.sleep(1)
    
    def stop_processing(self):
        """停止处理"""
        self.is_running = False
        logger.info("停止流量数据处理")

if __name__ == "__main__":
    processor = FlowProcessor()
    processor.start_processing()