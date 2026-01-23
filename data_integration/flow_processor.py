#!/usr/bin/env python3
# -*- coding=utf-8 -*-
import sys
import os
import time
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
import joblib
import numpy as np
from threading import Thread
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import paramiko
import threading

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)
try:
    from config import DATABASE_PATH, CHECK_INTERVAL
except ImportError:
    DATABASE_PATH = "netflow.db"
    CHECK_INTERVAL = 5

# ========== 日志升级核心 ==========
from utils.log_utils import get_module_logger
logger = get_module_logger("flow_processor")  # 日志文件：processor.log

# ========== 日志升级结束 ==========

# KDD 41维特征列（和run_system.py完全一致）
NETFLOW_FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]


# 全局加载模型（只加载一次）
try:
    model_path = os.path.join(PROJECT_ROOT, "models", "netflow_model_merge.pkl")
    scaler_path = os.path.join(PROJECT_ROOT, "models", "scaler.pkl")
    logging.info(f"开始加载模型 | 模型路径：{model_path} | 标准化器路径：{scaler_path}")
    
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    if hasattr(model, 'classes_'):
        logging.info(f"模型加载成功 | 分类类别：{model.classes_} | 异常类对应索引：{np.where(model.classes_ == 1)[0][0]}")
    logging.info(f"标准化器加载成功 | 特征维度：{scaler.n_features_in_} | 模型类型：{type(model).__name__}")
except Exception as e:
    logging.error(f"模型加载失败：{str(e)} | 异常类型：{type(e).__name__}")
    model = None
    scaler = None

class FlowProcessor:
    """流量处理器（异常检测）"""
    def __init__(self):
        self.db_path = DATABASE_PATH
    
    # 从数据库加载参数（正确逻辑）
        self.config = self.load_model_config()
        self.check_interval = self.config["check_interval"]
        self.batch_size = self.config["batch_size"]  # 从配置读取
        self.base_threshold = self.config["base_threshold"]
        self.block_threshold = self.config["block_threshold"]
        self.keep_days = self.config["keep_days"]
    
        self.is_running = False
    # 删掉这行！避免覆盖配置的batch_size
    # self.batch_size = 100  # 重复赋值，导致配置失效
    
        self.model = model
        self.scaler = scaler
        self.recent_anomaly_scores = []
        self.anomaly_cache = []
        self.last_alert_time = time.time()
        logging.info(f"初始化处理器 | 检测间隔：{self.check_interval}s | 批次大小：{self.batch_size}")
        time.sleep(3)
        self.ensure_database()

    def ensure_database(self):
        """确保数据库表存在"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # 1. 先检查netflow表是否有is_processed字段，没有则自动添加
            cursor.execute("PRAGMA table_info(netflow);")
            columns = [col[1] for col in cursor.fetchall()]  # 提取所有字段名
            logging.info(f"检查netflow表结构 | 当前字段：{columns}")
            if 'is_processed' not in columns:
                cursor.execute("ALTER TABLE netflow ADD COLUMN is_processed INTEGER DEFAULT 0;")
                logging.info(f"已自动为netflow表添加is_processed字段（路径：{self.db_path}）")
            else:
                logging.info(f"netflow表已存在is_processed字段（路径：{self.db_path}）")
            
            # 2. 检查anomaly_records表
            cursor.execute("PRAGMA table_info(anomaly_records);")
            anomaly_columns = [col[1] for col in cursor.fetchall()]
            if "is_false" not in anomaly_columns:
                 cursor.execute("ALTER TABLE anomaly_records ADD COLUMN is_false INTEGER DEFAULT 0;")
            logging.info(f"检查anomaly_records表结构 | 当前字段：{anomaly_columns}")
            
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomaly_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,  -- 建表时直接添加，关联netflow的id
                src_ip TEXT,
                dst_ip TEXT,
                in_bytes INTEGER,
                out_bytes INTEGER,  -- 新增出字节数
                in_packets INTEGER,
                out_packets INTEGER,  -- 新增出包数
                anomaly_score FLOAT,
                timestamp INTEGER,
                is_false INTEGER DEFAULT 0,
                FOREIGN KEY (flow_id) REFERENCES netflow(id)  -- 外键关联（可选，增强数据完整性）
            )
            """)
            conn.commit()
            logging.info("数据库表检查/创建完成")
        except Exception as e:
            logging.error(f"数据库表初始化失败：{str(e)} | 异常类型：{type(e).__name__}")
        finally:
            if 'conn' in locals():
                conn.close()

 # 新增：加载模型参数（从model_config表读取）
    def load_model_config(self):
        default_config = {
        "base_threshold": 0.4,
        "block_threshold": 0.8,
        "check_interval": 5,
        "batch_size": 100,
        "keep_days": 7,
        "alert_cache_threshold": 20
    }
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
        # 先检查model_config表是否存在
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='model_config';")
            if not cursor.fetchone():
                logging.warning("model_config表不存在，使用默认参数")
                conn.close()
                return default_config
        
        # 表存在则读取参数
            cursor.execute("SELECT param_name, param_value FROM model_config")
            results = cursor.fetchall()
            conn.close()
        
            for name, value in results:
                if name in default_config:
                    default_config[name] = value
            logging.info(f"成功加载模型参数：{default_config}")
            return default_config
        except Exception as e:
            logging.error(f"加载模型参数失败，使用默认值：{str(e)}")
            return default_config

    def get_new_flows(self):
        """获取未处理的新流量（解决重复检测）"""
        flows = []
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # 先统计未处理流量总数
            cursor.execute("SELECT COUNT(*) FROM netflow WHERE is_processed = 0;")
            total_unprocessed = cursor.fetchone()[0]
            logging.info(f"查询未处理流量 | 未处理流量总数：{total_unprocessed} | 本次查询批次：{self.batch_size}")
            
            # 查询具体流量数据
            cursor.execute("""
                SELECT id, src_ip, dst_ip, protocol, 
                   src_port, dst_port, in_bytes, out_bytes, in_packets,out_packets, timestamp,
                   first_switched, last_switched, tcp_flags  -- 新增
                FROM netflow
                WHERE is_processed = 0  -- 仅保留未处理条件
                ORDER BY id DESC
                LIMIT ?
            """, (self.batch_size,))
            flows = [dict(row) for row in cursor.fetchall()]
            if flows and 'id' not in flows[0]:
                logging.error("查询结果中缺少id字段！")
            else:
                logging.info(f"查询到未处理流量数量：{len(flows)} | 第一条流量id：{flows[0]['id'] if flows else '无'}")
            
            # 标记为已处理（注意：原代码是SET is_processed = 0，这里修正为1，否则会重复处理）
            if flows:
                flow_ids = [flow['id'] for flow in flows]
                cursor.executemany("UPDATE netflow SET is_processed = 1 WHERE id = ?", [(id,) for id in flow_ids])
                conn.commit()
                logging.info(f"已标记 {len(flow_ids)} 条流量为已处理 | 标记的ID：{flow_ids[:10]}...")
        
        except Exception as e:
            logging.error(f"获取未处理流量失败：{str(e)} | 异常类型：{type(e).__name__}")
        finally:
            if 'conn' in locals():
                conn.close()
        return flows

    def netflow_to_kdd_features(self, netflow_dict):
        """NetFlow→KDD 41维特征（全数字版，无字符串）"""
        try:
            kdd_data = {}
            logging.debug(f"开始转换流量特征 | 流量ID：{netflow_dict.get('id')} | 源IP：{netflow_dict.get('src_ip')} | 目的IP：{netflow_dict.get('dst_ip')}")
        
            # 1. 核心特征计算（duration是数值，无需转换）
            first_switched = netflow_dict.get('first_switched', 0)
            last_switched = netflow_dict.get('last_switched', 0)
            kdd_data['duration'] = max(0, last_switched - first_switched) # 修正：原代码是0，这里计算真实时长
            logging.debug(f"流量{netflow_dict.get('id')} | duration计算：last_switched({last_switched}) - first_switched({first_switched}) = {kdd_data['duration']}")
        
            # 2. 协议类型：直接转数字（无字符串）
            proto_map = {6: 1, 17: 2, 1: 3, 0: 0}
            protocol = netflow_dict.get('protocol', 0)
            kdd_data['protocol_type'] = proto_map.get(protocol, 0)
            logging.debug(f"流量{netflow_dict.get('id')} | 协议转换：{protocol} → {kdd_data['protocol_type']}")
        
            # 3. TCP标志位：先转字符串再转数字（保留原有逻辑+补数字映射）
            tcp_flag_map = {0: 0, 2: 1, 16: 2, 18: 3}
            tcp_flags = netflow_dict.get('tcp_flags', 0)
            kdd_data['flag'] = tcp_flag_map.get(tcp_flags, 0)  # 无对应字段，暂时设为0
            logging.debug(f"流量{netflow_dict.get('id')} | TCP标志：{kdd_data['flag']}")
        
            # 4. 基础数值特征（本身就是数字，直接赋值）
            kdd_data['src_bytes'] = netflow_dict.get('in_bytes', 0)
            kdd_data['dst_bytes'] = netflow_dict.get('out_bytes', 0)
            
            in_packets = netflow_dict.get('in_packets', 0)
            out_packets = netflow_dict.get('out_packets', 0)
            total_packets = in_packets + out_packets
            kdd_data['count'] = total_packets    # 核心特征count用总数据包
            kdd_data['srv_count'] = out_packets  # 服务端数据包数（出包）
            logging.debug(f"流量{netflow_dict.get('id')} | 基础特征：src_bytes={kdd_data['src_bytes']}, count={kdd_data['count']}")
        
            # 错误率相关：基于出包计算
            kdd_data['serror_rate'] = 0.0 if total_packets == 0 else (out_packets / total_packets)
            kdd_data['rerror_rate'] = 0.0 if in_packets == 0 else (in_packets / total_packets)

            # 5. 服务名：先端口→字符串再转数字（保留原有逻辑+补数字映射）
            dst_port = netflow_dict.get('dst_port', 0)
            port_service_num_map = {80: 1, 443: 2, 53: 3, 21: 4, 22: 5, 389: 6, 25: 7, 110: 8, 143: 9, 3389: 10}
            kdd_data['service'] = port_service_num_map.get(dst_port, 0)
            logging.debug(f"流量{netflow_dict.get('id')} | 服务转换：目的端口{dst_port} → {kdd_data['service']}")
        
            # 6. 补全41维特征（无数据填0，全是数字）
            for col in NETFLOW_FEATURE_COLUMNS:
                if col not in kdd_data:
                    kdd_data[col] = 0  # 所有缺失特征填0（数字）
            
            # 7. 按顺序返回纯数字列表
            feature_list = [kdd_data[col] for col in NETFLOW_FEATURE_COLUMNS]
            logging.debug(f"流量{netflow_dict.get('id')} | 特征转换完成 | 特征长度：{len(feature_list)} | 前5维特征：{feature_list[:5]}")
            return feature_list
        except Exception as e:
            logging.error(f"流量{netflow_dict.get('id')}特征转换失败：{str(e)} | 异常类型：{type(e).__name__}")
            return [0]*41  # 转换失败返回全0特征

    def detect_anomaly(self, flows):
        """异常检测"""
        if not flows:
            logging.info("检测跳过：无流量数据")
            return 0
        if not self.model or not self.scaler:
            logging.error("检测跳过：模型或标准化器未加载")
            return 0
        
        logging.info(f"=== 开始检测 | 模型类型：{type(self.model).__name__} | 流量数量：{len(flows)} ===")
        # 提取特征
        features = []
        flow_info = []
        for idx, flow in enumerate(flows):
            feat = self.netflow_to_kdd_features(flow)
            features.append(feat)
            flow_info.append({
                'flow_id': flow['id'],
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'in_bytes': flow['in_bytes'],
                'out_bytes': flow['out_bytes'],  # 新增
                'in_packets': flow['in_packets'],
                'out_packets': flow['out_packets'],  # 新增
                'timestamp': flow['timestamp']
            })
            if idx == 0:
                logging.info(f"第1条流量特征示例：{feat[:5]}...（总维度：{len(feat)}）")
        
        # 纯数字数组+标准化
        try:
            features_array = np.array(features)
            logging.info(f"特征数组形状：{features_array.shape} | 训练时特征维度：{self.scaler.n_features_in_}")  # 确认维度匹配
            
            # 校验特征维度
            if features_array.shape[1] != self.scaler.n_features_in_:
                logging.error(f"特征维度不匹配！当前特征维度：{features_array.shape[1]} | 标准化器期望维度：{self.scaler.n_features_in_}")
                return 0
            
            scaled_features = self.scaler.transform(features_array)
            logging.info(f"第1条流量标准化后特征：{scaled_features[0][:5]}... | 标准化后数组形状：{scaled_features.shape}")
        
            # 预测
            predictions = self.model.predict(scaled_features)
            scores = self.model.predict_proba(scaled_features)[:, 1]
            logging.info(f"=== 预测结果 ===")
            logging.info(f"预测数组形状：predictions={predictions.shape}, scores={scores.shape}")
            logging.info(f"异常概率范围：[{scores.min():.4f}, {scores.max():.4f}] | 预测值分布：正常({np.sum(predictions==0)}), 异常({np.sum(predictions==1)})")
            
            for idx, (info, prob, pred) in enumerate(zip(flow_info, scores, predictions)):
                logging.info(
                    f"流量{idx+1} | ID：{info['flow_id']} | 源IP：{info['src_ip']}  | 目的IP：{info['dst_ip']} | 异常概率：{prob:.4f} | 预测结果：{'异常' if pred == 1 else '正常'}"
                )

            logging.info(f"flow_info长度：{len(flow_info)} | scores长度：{len(scores)} | predictions长度：{len(predictions)}")
            assert len(flow_info) == len(scores) == len(predictions), "检测数据长度不匹配！"

            # 记录异常
                # 新逻辑：根据最近10+个分数计算动态阈值
            if len(self.recent_anomaly_scores) > 10:
            # 取最近分数的75分位数 + 0.1（避免误报），上限0.8（避免漏报）
                threshold = np.percentile(self.recent_anomaly_scores, 75) + 0.1
                anomaly_threshold = min(threshold, self.base_threshold)
            else:
                anomaly_threshold = self.base_threshold  # 初始阶段用固定阈值
    
            # 记录当前批次的异常分数（只保留最近100个）
            self.recent_anomaly_scores.extend(scores)
            if len(self.recent_anomaly_scores) > 100:
                self.recent_anomaly_scores = self.recent_anomaly_scores[-100:]  # 只留最后100个

            logging.info(f"异常判断阈值：{anomaly_threshold}")
            anomaly_count = 0
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for i, (info, prob, pred) in enumerate(zip(flow_info, scores, predictions)):
                logging.debug(f"处理异常记录{i+1} | info内容：{info} | 是否包含flow_id：{'flow_id' in info}")
                
                if prob >= anomaly_threshold:  # 用概率判断更准确
                    anomaly_count += 1
                    cursor.execute("""
                    INSERT INTO anomaly_records (flow_id, src_ip, dst_ip,in_bytes,out_bytes, in_packets, out_packets, anomaly_score, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (info['flow_id'], info['src_ip'], info['dst_ip'], info['in_bytes'], info['out_bytes'], info['in_packets'], info['out_packets'], prob, info['timestamp']))
             # -------------------------- 新增：调用QQ邮箱告警 --------------------------
        # 构造告警内容（清晰显示异常信息）
                    alert_content = f"""
【NetFlow异常流量告警详情】
1. 异常流量ID：{info['flow_id']}
2. 源IP地址：{info['src_ip']}
3. 目的IP地址：{info['dst_ip']}
4. 流量数据：入字节{info['in_bytes']} | 出字节{info['out_bytes']} | 入包{info['in_packets']} | 出包{info['out_packets']}
5. 异常概率：{prob:.4f}（阈值{anomaly_threshold}）
6. 发生时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['timestamp']))}
"""
                    self.anomaly_cache.append(alert_content)  # 缓存到列表
                                        # 高风险异常时调用阻断函数
                    if prob >= self.block_threshold:
                        self.block_ip_via_router(info['src_ip'])  # 调用新增的阻断函数

            conn.commit()
            logging.info(f"成功插入 {anomaly_count} 条异常记录到anomaly_records表")

            
        except Exception as e:
            current_i = i if 'i' in locals() else '未执行到循环'
            current_info = info if 'info' in locals() else '无'
            logging.error(f"异常检测过程失败 | 当前循环位置：{current_i} | 当前info：{current_info} | 错误：{str(e)}")
            anomaly_count = 0
        finally:
            if 'conn' in locals():
                conn.close()
        
        logging.info(f"=== 检测完成 | 异常数量：{anomaly_count} ===")
        return anomaly_count

    def start_processing(self):
        """启动处理器"""
        #日志
      

        self.is_running = True
        logging.info("=== 数据处理器启动成功 ===")
        logging.info(f"检测间隔：{self.check_interval}秒 | 批次大小：{self.batch_size} | 数据库路径：{self.db_path}")
        
        # 标记是否已清理过（避免一天多次清理）
        has_cleaned_today = False

        while self.is_running:
            
            current_time = time.time()
            time_diff = current_time - self.last_alert_time
            current_local_time = time.localtime(current_time)
            current_hour = current_local_time.tm_hour  

            cache_len = len(self.anomaly_cache)
            logging.info(f"当前系统时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time))}")
            logging.info(f"距上次告警时间差：{time_diff:.2f}秒 | 缓存异常数：{cache_len}")

            if (time_diff >= 30) and cache_len > 0:
                    # 合并缓存的所有异常
                    total_content = f"【NetFlow异常汇总告警】\n近10分钟共检测到{len(self.anomaly_cache)}条异常，详情如下：\n" + "".join(self.anomaly_cache)
                    self.send_qq_email_alert(total_content)
                    # 重置缓存和时间
                    self.anomaly_cache = []
                    self.last_alert_time = current_time
                    logging.info(f"告警发送完成 | 缓存已清空 | 上次告警时间重置为：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time))}")

                # 紧急条件：10分钟内异常数>20，立即发告警
            elif len(self.anomaly_cache) > 20:
                    total_content = f"【紧急】NetFlow异常激增告警\n10分钟内已检测到{len(self.anomaly_cache)}条异常，详情如下：\n" + "".join(self.anomaly_cache)
                    self.send_qq_email_alert(total_content)
                    self.anomaly_cache = []
                    self.last_alert_time = current_time
            
                   #每天凌晨3点清理旧数据
            if current_hour == 3 and not has_cleaned_today:
                    self.clean_old_data(keep_days=7)  # 保留7天数据
                    has_cleaned_today = True  # 标记今天已清理
            # 不是3点时，重置标记（确保第二天3点能清理）
            elif current_hour != 3:
                    has_cleaned_today = False
            
            
            try:
           


                logging.info("=== 开始新一轮检测循环 ===")
                flows = self.get_new_flows()
                
                if not flows:
                    logging.info("本轮无未处理流量，等待下一次检测")
                    time.sleep(self.check_interval)
                    continue
                
                logging.info(f"开始处理 {len(flows)} 条流量数据 | 流量ID范围：{flows[0]['id']} ~ {flows[-1]['id']}")
                anomaly_count = self.detect_anomaly(flows)
                
                if anomaly_count == 0:
                    logging.info(f"本轮检测完成 | 未检测到异常流量 | 处理流量数：{len(flows)}")
                else:
                    logging.warning(f"本轮检测完成 | 检测到 {anomaly_count} 条异常流量 | 处理流量数：{len(flows)}")
                
                

            except Exception as e:
                logging.error(f"处理器运行失败：{str(e)} | 异常类型：{type(e).__name__}")
            finally:
                logging.info(f"本轮检测循环结束，等待{self.check_interval}秒后继续")
                time.sleep(self.check_interval)

    def stop(self):
        """停止处理器"""
        self.is_running = False
        logging.info("=== 数据处理器已停止 ===")
        # 在flow_processor.py中新增清理函数

# -------------------------- 新增：QQ邮箱告警方法 --------------------------
    def send_qq_email_alert(self, content):
        """QQ邮箱告警：检测到异常时自动发邮件（无需建群，单人可用）"""
        
        # 配置你的QQ邮箱信息（必须改这里！）
        sender_qq = "584958612@qq.com"  # 比如12345678@qq.com
        sender_auth_code = "uxetzsclyqkvbcig"  # 不是QQ密码，获取方法见下方说明
        receiver_qq = "584958612@qq.com"  # 可以和sender_qq一样，给自己发
        
        try:
            logging.info(f"开始发送QQ邮箱告警 | 收件人：{receiver_qq}")
            # 1. 配置邮件内容
            message = MIMEText(content, 'plain', 'utf-8')
            message['From'] = sender_qq  # 去掉Header，直接用字符串格式
            message['To'] = Header(receiver_qq, 'utf-8')  # 收件人
            message['Subject'] = Header("【紧急】NetFlow异常流量告警", 'utf-8')  # 邮件标题
            
            # 2. 连接QQ邮箱SMTP服务器
            smtp_obj = smtplib.SMTP_SSL('smtp.qq.com', 465)  # QQ邮箱固定服务器和端口
            smtp_obj.login(sender_qq, sender_auth_code)  # 登录
            smtp_obj.sendmail(sender_qq, receiver_qq, message.as_string())  # 发送邮件
            smtp_obj.quit()
            
            logging.info("异常告警已发送到QQ邮箱！")
        except Exception as e:
            logging.error(f"QQ邮箱告警发送失败：{str(e)} | 检查QQ号和授权码是否正确")

    # -------------------------- 新增：清理旧数据方法（移到类内） --------------------------
    def clean_old_data(self, keep_days=7):
        """清理超过N天的历史数据（避免数据库撑爆）"""
        try:
            conn = sqlite3.connect(self.db_path)  # 类内可直接用self.db_path
            cursor = conn.cursor()
            # 计算7天前的时间戳（秒）
            expire_ts = int(time.time()) - keep_days * 86400
            # 清理netflow表：只删已处理的旧数据
            cursor.execute("DELETE FROM netflow WHERE is_processed=1 AND timestamp < ?", (expire_ts,))
            # 清理异常表：删旧异常记录
            cursor.execute("DELETE FROM anomaly_records WHERE timestamp < ?", (expire_ts,))
            conn.commit()
            logging.info(f"清理完成：删除{cursor.rowcount}条过期数据（保留近{keep_days}天）")
        except Exception as e:
            logging.error(f"清理旧数据失败：{str(e)}")
        finally:
            if 'conn' in locals():
                conn.close()

                    # 新增：路由器SSH阻断函数（写在FlowProcessor类内）
    def block_ip_via_router(self, src_ip):
        router_config = {
            'host': '192.168.10.1',
            'username': 'cisco',
            'password': 'cisco'
        }
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(**router_config, timeout=10)
            
            commands = [
                'enable',
                'cisco',
                'configure terminal',
                f'access-list 100 deny ip host {src_ip} any',
                'access-list 100 permit ip any any',
                'interface FastEthernet1/0',
                'ip access-group 100 in',
                'exit',
                'write memory'
            ]
            ssh.exec_command('\n'.join(commands))
            ssh.close()
            logging.info(f"GNS3路由器已阻断IP：{src_ip}")

                    # 新增：写入阻断记录到blocked_ips表
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR IGNORE INTO blocked_ips (ip, reason, block_time)
            VALUES (?, ?, strftime('%s', 'now'))
        """, (src_ip, '模型自动阻断（高风险异常）'))
            conn.commit()
            conn.close()
            logging.info(f"阻断记录已写入数据库：{src_ip}")

            threading.Timer(3600, self.unblock_ip_via_router, args=(src_ip,)).start()
        except Exception as e:
            logging.error(f"GNS3路由器阻断失败：{str(e)}")

    # 新增：路由器SSH解除阻断函数（写在FlowProcessor类内）
    def unblock_ip_via_router(self, src_ip):
        router_config = {
            'host': '192.168.10.1',
            'username': 'cisco',
            'password': 'cisco'
        }
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(**router_config, timeout=10)
            
            commands = [
                'enable',
                'cisco',
                'configure terminal',
                f'no access-list 100 deny ip host {src_ip} any',
                'write memory'
            ]
            ssh.exec_command('\n'.join(commands))
            ssh.close()
            logging.info(f"已解除GNS3路由器对IP {src_ip} 的阻断")

                    # 新增：从blocked_ips表删除记录
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (src_ip,))
            conn.commit()
            conn.close()
            logging.info(f"阻断记录已从数据库删除：{src_ip}")

        except Exception as e:
            logging.error(f"GNS3路由器解除阻断失败：{str(e)}")




# 启动处理器
if __name__ == "__main__":
    try:
        processor = FlowProcessor()
        processor.start_processing()
    except KeyboardInterrupt:
        logging.info("接收到停止信号，正在关闭处理器...")
        processor.stop()
    except Exception as e:
        logging.critical(f"处理器启动失败：{str(e)} | 异常类型：{type(e).__name__}")
        sys.exit(1)