# config.py - 补全所有真实配置，统一管理
import os

# ============== 1. 基础路径配置（自动推导，避免硬编码绝对路径）==============
# 项目根目录（根据config.py自身路径自动计算，不用手动改）
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))  # 对应你的项目根目录
# 前端文件路径（给flask_server用）
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "web", "public")
# 数据库路径（真实路径，和collector_v9.py、flow_processor.py统一）
DATABASE_PATH = os.path.join(PROJECT_ROOT, "netflow.db")  # 替换成你的真实路径（如D:\...\netflow.db）
# 模型文件路径（给flow_processor用）
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "netflow_model_merge.pkl")  # 你的真实模型路径
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")  # 你的真实标准化器路径

# ============== 2. NetFlow采集配置（给main.py/collector_v9.py用）==============
NETFLOW_CONFIG = {
    "host": "0.0.0.0",
    "port": 9995  # 你实际的NetFlow监听端口
}
BATCH_WRITE_THRESHOLD = 50

# ============== 3. 路由器配置（给flow_processor.py的阻断功能用）==============
ROUTER_CONFIG = {
    "host": "192.168.10.1",  # 你的GNS3路由器真实IP
    "username": "cisco",      # 路由器真实用户名
    "password": "cisco",      # 路由器真实密码
    "enable_password": "cisco",# 路由器enable密码（如果有）
    "interface": "FastEthernet0/0"  # 路由器真实接口（如Fa0/0）
}

# ============== 4. 异常检测配置（给flow_processor.py用）==============
ANOMALY_CONFIG = {
    "base_threshold": 0.4,    # 动态阈值基础（真实值）
    "block_threshold": 0.8,   # 高风险阻断阈值（真实值）
    "check_interval": 5,      # 模型检测间隔（秒，真实值）
    "batch_size": 100,        # 批次处理大小（真实值）
    "keep_days": 7,           # 数据保留天数（真实值）
    "alert_cache_threshold": 20  # 异常缓存告警阈值（真实值）
}

# ============== 5. Web服务配置（给flask_server.py/main.py用）==============
WEB_CONFIG = {
    "host": "0.0.0.0",
    "port": 8000,  # 你实际的Web端口
    "debug": True  # 生产环境改False
}

# ============== 6. 监控配置（给main.py用）==============
MONITOR_CONFIG = {
    "interval": 30  # 监控刷新间隔（秒，真实值）
}

# ============== 7. 邮箱告警配置（给flow_processor.py用）==============
EMAIL_CONFIG = {
    "sender_qq": "584958612@qq.com",  # 你的真实QQ邮箱
    "sender_auth_code": "uxetzsclyqkvbcig",  # 你的真实授权码
    "receiver_qq": "584958612@qq.com"  # 接收告警的邮箱

}

# ========== 全局日志配置（统一管理） ==========
LOG_CONFIG = {
    "level": "DEBUG",  # 全局日志级别：DEBUG（详细）/ INFO（精简）/ WARNING（仅警告）/ ERROR（仅错误）
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    "datefmt": "%Y-%m-%d %H:%M:%S",
    "log_dir": "logs",  # 日志文件存放在项目根目录的logs文件夹
    "max_bytes": 10 * 1024 * 1024,  # 单个日志文件最大10MB
    "backup_count": 5,  # 最多保留5个备份日志（超过自动删除最旧的）
    "console_output": True  # 开启控制台输出（关闭则只写文件，不显示在控制台）
}
MODULE_LOG_MAP = {
            "main": "main.log",                # 主程序（main.py）
            "collector_v9": "collector_v9.log",# 流量采集（collector_v9.py）
            "flow_processor": "flow_processor.log",# 流量处理+异常检测（flow_processor.py）
            "flask_server": "flask.log",       # Flask后端（flask_server.py）
            "anomaly_routes": "flask.log",     # 后端路由（归到flask日志）
            "model_train": "model_train.log",  # 模型训练（model_train_pipeline.py）
            "config": "main.log"               # 配置模块（归到主程序）
        }
GLOBAL_ERROR_LOG = "error.log"

# ===================== 【新增】模型训练相关配置 ======================
# 数据集路径
DATASET_ROOT = os.path.join(PROJECT_ROOT, "data")  # 数据集根文件夹
MERGED_DATASET_PATH = os.path.join(DATASET_ROOT, "merged_netflow_data.csv")  # 合并后数据集保存路径


# 模型与日志保存路径
MODEL_PREFIX = "netflow_model_"
MODEL_SAVE_DIR = os.path.join(PROJECT_ROOT, "models")  # 模型文件夹
MODEL_SAVE_PATH = os.path.join(MODEL_SAVE_DIR, "netflow_model_merge.pkl")  # 训练好的模型路径
TRAIN_LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "model_train.log")  # 训练日志路径
TRAIN_METRICS_PATH = os.path.join(MODEL_SAVE_DIR, "train_metrics.txt")  # 训练指标保存路径

# 随机森林超参数
RF_N_ESTIMATORS = 100  # 决策树数量
RF_MAX_DEPTH = 20      # 树最大深度


# ============== 8. 确保目录存在（自动创建，不用手动建）==============
for dir_path in [FRONTEND_DIR, MODEL_DIR, os.path.dirname(DATABASE_PATH)]:
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)