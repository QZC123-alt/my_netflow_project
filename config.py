
# 配置文件 - 连接三个项目的设置

# 数据库配置（来自mnet）
DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': 'password',
    'database': 'netflow_analysis'
}

# 异常检测配置（来自ai-network-anomaly）
ANOMALY_DETECTION_CONFIG = {
    'model_path': 'models/rf_model.pkl',
    'threshold': 0.8,
    'feature_columns': ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'bytes']
}

# 数据包捕获配置（来自packet_analysis）
PACKET_CAPTURE_CONFIG = {
    'interface': 'eth0',
    'filter': 'tcp or udp',
    'timeout': 1000
}

# Web界面配置（来自mnet）
WEB_CONFIG = {
    'host': '0.0.0.0',
    'port': 8000,
    'debug': True
}


# 数据库配置
DATABASE_PATH = r"D:\VS\project\Python\Python_Netflow\netflow.db"  # 绝对路径，避免找不到

# NetFlow配置
NETFLOW_HOST = '0.0.0.0'
NETFLOW_PORT = 9995  # 使用您现有的端口

# 异常检测配置
ANOMALY_THRESHOLD = 0.8
CHECK_INTERVAL = 5  # 秒

# 监控配置
MONITOR_INTERVAL = 30  # 秒