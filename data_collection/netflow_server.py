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

# 导入配置
try:
    from config import DATABASE_PATH, CHECK_INTERVAL
except ImportError:
    DATABASE_PATH = 'netflow.db'
    CHECK_INTERVAL = 5

from anomaly_detection.simple_detector import SimpleAnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FlowProcessor:
    """连接数据收集和异常检测的桥梁"""
    
    def __init__(self):
        self.db_path = DATABASE_PATH
        self.detector = SimpleAnomalyDetector()
        self.is_running = False
        self.check_interval = CHECK_INTERVAL
        
        # 等待数据库初始化完成
        time.sleep(3)
        self.ensure_database()
        
    def ensure_database(self):
        """确保数据库和表存在"""
        try:
            # 导入collector_v9的createdb函数
            from data_collection.collector_v9 import createdb
            createdb()
            logger.info("数据库检查完成")
        except Exception as e:
            logger.error(f"数据库初始化失败: {e}")
    
    def get_new_flows(self):
        """从数据库获取最新的流记录"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 先检查表是否存在
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='flowdata'
            """)
            table_exists = cursor.fetchone()
            
            if not table_exists:
                logger.warning("flowdata表不存在，尝试重新创建")
                conn.close()
                self.ensure_database()
                return            
            # 获取最近的流记录
            cursor.execute("""
                SELECT in_bytes, out_bytes, protocol, in_pkts, l4_src_port, l4_dst_port 
                FROM flowdata 
                WHERE ID > (SELECT COALESCE(max(ID), 0) FROM flowdata) - 10
                ORDER BY ID DESC
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
                    'timestamp': time.time(),
                    'in_bytes': flow[0],
                    'out_bytes': flow[1], 
                    'protocol': flow[2],
                    'in_pkts': flow[3],
                    'src_port': flow[4],
                    'dst_port': flow[5]
                }
                
                # 进行异常检测
                result = self.detector.analyze_flow(flow_data)
                
                if result and result['is_anomaly']:
                    logger.warning(f"⚠️  发现异常流量! 分数: {result['score']:.2f}")
                    self.handle_anomaly(flow_data, result)
        else:
            logger.debug("没有新的流数据")
    
    def handle_anomaly(self, flow_data, result):
        """处理异常检测结果"""
        logger.warning(f"异常详情: {flow_data}")
        logger.warning(f"检测结果: {result}")
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