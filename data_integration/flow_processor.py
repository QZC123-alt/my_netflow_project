# flow_processor.py - 修复未处理流量查询+异常检测
import sys
import os
import time
import sqlite3
import logging
import joblib
import numpy as np
import paramiko
import threading
from threading import Thread
import smtplib
from email.mime.text import MIMEText
from email.header import Header

# 项目路径
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)
from config import (
    DATABASE_PATH, MODEL_PATH, SCALER_PATH,
    ROUTER_CONFIG, ANOMALY_CONFIG, EMAIL_CONFIG
)
from utils.log_utils import get_module_logger
logger = get_module_logger("flow_processor")

# KDD 41维特征列
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
model = None
scaler = None
try:
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        logger.info(f"✅ 模型加载成功（类型：{type(model).__name__}，特征维度：{scaler.n_features_in_}）")
    else:
        logger.warning(f"⚠️ 模型文件缺失（模型：{MODEL_PATH}，标准化器：{SCALER_PATH}）")
except Exception as e:
    logger.error(f"❌ 模型加载失败：{str(e)}", exc_info=True)

class FlowProcessor:
    def __init__(self):
        self.db_path = DATABASE_PATH
        self.config = ANOMALY_CONFIG.copy()
        self.load_model_config()  # 从数据库加载配置
        self.is_running = False
        self.model = model
        self.scaler = scaler
        self.recent_anomaly_scores = []
        self.anomaly_cache = []
        self.last_alert_time = time.time()
        self.ensure_database()
        logger.info(f"✅ 处理器初始化完成（检测间隔：{self.config['check_interval']}s，批次大小：{self.config['batch_size']}）")

    def ensure_database(self):
        """确保数据库表存在"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # 检查netflow表字段
            cursor.execute("PRAGMA table_info(netflow);")
            columns = [col[1] for col in cursor.fetchall()]
            if 'is_processed' not in columns:
                cursor.execute("ALTER TABLE netflow ADD COLUMN is_processed INTEGER DEFAULT 0;")
                logger.info("✅ 为netflow表添加is_processed字段")

            # 检查anomaly_records表
            cursor.execute("PRAGMA table_info(anomaly_records);")
            anomaly_cols = [col[1] for col in cursor.fetchall()]
            if "is_false" not in anomaly_cols:
                cursor.execute("ALTER TABLE anomaly_records ADD COLUMN is_false INTEGER DEFAULT 0;")
                logger.info("✅ 为anomaly_records表添加is_false字段")

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"❌ 数据库检查失败：{str(e)}")

    def load_model_config(self):
        """从数据库加载配置（覆盖默认值）"""
        default_config = {
            "base_threshold": 0.4,
            "block_threshold": 0.8,
            "check_interval": 5,
            "batch_size": 50,
            "keep_days": 7,
            "alert_cache_threshold": 20
        }
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT param_name, param_value FROM model_config")
            results = cursor.fetchall()
            conn.close()

            for name, value in results:
                if name in default_config:
                    default_config[name] = float(value)
            self.config.update(default_config)
            logger.info(f"✅ 从数据库加载配置：{self.config}")
        except Exception as e:
            logger.warning(f"⚠️ 加载配置失败，使用默认值：{str(e)}")
            self.config = default_config

    def get_new_flows(self):
        """获取未处理的流量（核心修复：确保查到数据）"""
        flows = []
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # 先统计所有流量状态（关键：排查数据分布）
            cursor.execute("SELECT is_processed, COUNT(*) FROM netflow GROUP BY is_processed;")
            status_count = cursor.fetchall()
            status_msg = ", ".join([f"is_processed={s}: {c}条" for s, c in status_count])
            logger.info(f"🔍  netflow表流量状态：{status_msg}")

            # 查询未处理流量（is_processed=0）
            cursor.execute("""
                SELECT id, src_ip, dst_ip, protocol, 
                       src_port, dst_port, in_bytes, out_bytes, in_packets, out_packets, timestamp,
                       first_switched, last_switched, tcp_flags
                FROM netflow
                WHERE is_processed = 0
                ORDER BY id DESC
                LIMIT ?
            """, (int(self.config['batch_size']),))
            flows = [dict(row) for row in cursor.fetchall()]

            # 标记为已处理（避免重复查询）
            if flows:
                flow_ids = [str(flow['id']) for flow in flows]
                cursor.executemany("UPDATE netflow SET is_processed = 1 WHERE id = ?", [(fid,) for fid in flow_ids])
                conn.commit()
                logger.info(f"✅ 标记{len(flows)}条流量为已处理（ID：{', '.join(flow_ids[:5])}...）")
            else:
                logging.info(f"ℹ️  未查询到未处理流量（is_processed=0）")

            conn.close()
        except Exception as e:
            logger.error(f"❌ 获取未处理流量失败：{str(e)}", exc_info=True)
        return flows

    def netflow_to_kdd_features(self, netflow_dict):
        """NetFlow转KDD 41维特征"""
        try:
            kdd_data = {}
            flow_id = netflow_dict.get('id', '未知')

            # 1. 计算duration（秒级）
            first_switched = netflow_dict.get('first_switched', 0)
            last_switched = netflow_dict.get('last_switched', 0)
            kdd_data['duration'] = max(0, (last_switched - first_switched) / 1000)  # 毫秒转秒

            # 2. 协议类型（数字映射）
            proto_map = {6: 1, 17: 2, 1: 3, 0: 0}
            kdd_data['protocol_type'] = proto_map.get(netflow_dict.get('protocol', 0), 0)

            # 3. TCP标志位
            tcp_flag_map = {0: 0, 2: 1, 16: 2, 18: 3}
            kdd_data['flag'] = tcp_flag_map.get(netflow_dict.get('tcp_flags', 0), 0)

            # 4. 基础数值特征
            kdd_data['src_bytes'] = netflow_dict.get('in_bytes', 0)
            kdd_data['dst_bytes'] = netflow_dict.get('out_bytes', 0)
            in_packets = netflow_dict.get('in_packets', 0)
            out_packets = netflow_dict.get('out_packets', 0)
            kdd_data['count'] = in_packets + out_packets
            kdd_data['srv_count'] = out_packets

            # 5. 错误率
            total_packets = kdd_data['count']
            kdd_data['serror_rate'] = 0.0 if total_packets == 0 else (out_packets / total_packets)
            kdd_data['rerror_rate'] = 0.0 if in_packets == 0 else (in_packets / total_packets)

            # 6. 服务名（端口映射）
            port_map = {80: 1, 443: 2, 53: 3, 21: 4, 22: 5, 389: 6, 25: 7, 110: 8, 143: 9, 3389: 10}
            kdd_data['service'] = port_map.get(netflow_dict.get('dst_port', 0), 0)

            # 7. 补全41维特征
            for col in NETFLOW_FEATURE_COLUMNS:
                if col not in kdd_data:
                    kdd_data[col] = 0.0

            # 转为特征列表
            feature_list = [kdd_data[col] for col in NETFLOW_FEATURE_COLUMNS]
            logger.debug(f"✅ 流量{flow_id}特征转换完成（前5维：{feature_list[:5]}）")
            return feature_list
        except Exception as e:
            logger.error(f"❌ 流量{netflow_dict.get('id')}特征转换失败：{str(e)}")
            return [0.0]*41

    def detect_anomaly(self, flows):
        """异常检测（核心逻辑）"""
        if not flows:
            return 0
        if not self.model or not self.scaler:
            logger.error("❌ 模型未加载，跳过异常检测")
            return 0

        try:
            # 提取特征
            features = [self.netflow_to_kdd_features(flow) for flow in flows]
            flow_info = [{
                'flow_id': flow['id'], 'src_ip': flow['src_ip'], 'dst_ip': flow['dst_ip'],
                'in_bytes': flow['in_bytes'], 'out_bytes': flow['out_bytes'],
                'in_packets': flow['in_packets'], 'out_packets': flow['out_packets'],
                'timestamp': flow['timestamp']
            } for flow in flows]

            # 标准化+预测
            features_array = np.array(features)
            scaled_features = self.scaler.transform(features_array)
            predictions = self.model.predict(scaled_features)
            scores = self.model.predict_proba(scaled_features)[:, 1]

            # 动态阈值计算
            if len(self.recent_anomaly_scores) > 10:
                threshold = np.percentile(self.recent_anomaly_scores, 75) + 0.1
                anomaly_threshold = min(threshold, self.config['base_threshold'])
            else:
                anomaly_threshold = self.config['base_threshold']
            self.recent_anomaly_scores = (self.recent_anomaly_scores + list(scores))[-100:]  # 保留最近100个

            # 写入异常记录
            anomaly_count = 0
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            for i, (info, prob, pred) in enumerate(zip(flow_info, scores, predictions)):
                if prob >= anomaly_threshold:
                    anomaly_count += 1
                    cursor.execute("""
                        INSERT INTO anomaly_records (flow_id, src_ip, dst_ip, in_bytes, out_bytes, in_packets, out_packets, anomaly_score, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (info['flow_id'], info['src_ip'], info['dst_ip'], info['in_bytes'], info['out_bytes'], info['in_packets'], info['out_packets'], prob, info['timestamp']))

                    # 高风险IP阻断（未开GNS3仅日志）
                    if prob >= self.config['block_threshold']:
                        logger.warning(f"⚠️ 高风险IP {info['src_ip']}（概率：{prob:.4f}），未开GNS3跳过阻断")
                        self.anomaly_cache.append(f"IP {info['src_ip']} 异常概率：{prob:.4f}")

            conn.commit()
            conn.close()
            logger.info(f"✅ 异常检测完成（处理{len(flows)}条流量，检测到{anomaly_count}条异常，阈值：{anomaly_threshold:.4f}）")
            return anomaly_count
        except Exception as e:
            logger.error(f"❌ 异常检测失败：{str(e)}", exc_info=True)
            return 0

    def start_processing(self):
        """启动处理器循环"""
        self.is_running = True
        logger.info("✅ 数据处理器启动成功")
        last_config_load = time.time()
        has_cleaned_today = False

        while self.is_running:
            current_time = time.time()

            # 每30秒刷新配置
            if current_time - last_config_load > 30:
                self.load_model_config()
                last_config_load = current_time

            # 每天凌晨3点清理旧数据
            current_hour = time.localtime(current_time).tm_hour
            if current_hour == 3 and not has_cleaned_today:
                self.clean_old_data()
                has_cleaned_today = True
            elif current_hour != 3:
                has_cleaned_today = False

            # 核心检测逻辑
            try:
                flows = self.get_new_flows()
                if flows:
                    self.detect_anomaly(flows)
                else:
                    time.sleep(self.config['check_interval'])
            except Exception as e:
                logger.error(f"❌ 处理器循环错误：{str(e)}", exc_info=True)
                time.sleep(self.config['check_interval'])

    def clean_old_data(self):
        """清理旧数据"""
        try:
            keep_days = self.config['keep_days']
            expire_ts = int(time.time()) - keep_days * 86400
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # 清理已处理的旧流量
            cursor.execute("DELETE FROM netflow WHERE is_processed=1 AND timestamp < ?", (expire_ts,))
            flow_del_count = cursor.rowcount

            # 清理旧异常记录
            cursor.execute("DELETE FROM anomaly_records WHERE timestamp < ?", (expire_ts,))
            anomaly_del_count = cursor.rowcount

            conn.commit()
            conn.close()
            logger.info(f"✅ 清理旧数据（保留{keep_days}天，删除流量：{flow_del_count}条，删除异常：{anomaly_del_count}条）")
        except Exception as e:
            logger.error(f"❌ 清理旧数据失败：{str(e)}")

    def stop(self):
        self.is_running = False
        logger.info("✅ 数据处理器已停止")

    def send_qq_email_alert(self, content):
        """邮箱告警（适配配置）"""
        try:
            sender = EMAIL_CONFIG["sender_qq"]
            auth_code = EMAIL_CONFIG["sender_auth_code"]
            receiver = EMAIL_CONFIG["receiver_qq"]

            msg = MIMEText(content, 'plain', 'utf-8')
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = Header("【NetFlow异常告警】", 'utf-8')

            smtp = smtplib.SMTP_SSL('smtp.qq.com', 465)
            smtp.login(sender, auth_code)
            smtp.sendmail(sender, receiver, msg.as_string())
            smtp.quit()
            logger.info("✅ 告警邮件发送成功")
        except Exception as e:
            logger.error(f"❌ 告警邮件发送失败：{str(e)}")

# 单独运行处理器
if __name__ == "__main__":
    try:
        processor = FlowProcessor()
        processor.start_processing()
    except KeyboardInterrupt:
        processor.stop()
    except Exception as e:
        logger.critical(f"❌ 处理器启动失败：{str(e)}", exc_info=True)
        sys.exit(1)