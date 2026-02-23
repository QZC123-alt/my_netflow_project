#!/usr/bin/env python3
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, precision_score
import joblib
import os
import logging
import platform  # 新增：系统兼容性
import numpy as np
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)
from config import (
    DATABASE_PATH, MODEL_PATH, SCALER_PATH,MODEL_DIR,DATASET_ROOT,PROJECT_ROOT,MODEL_PREFIX
)
sys.path.append(PROJECT_ROOT)
from utils.log_utils import get_module_logger
logger = get_module_logger("model_train")  # 日志文件

# -------------------------- 路径配置（跨系统兼容） --------------------------

# 直接指向项目根目录的data和models
DATA_DIR = DATASET_ROOT       # 根目录/data
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

# 组件保存路径（支持多模型共存）

FEATURE_ENCODERS_PATH = os.path.join(MODEL_DIR, "feature_encoders.pkl")  # 根目录/models/feature_encoders.pkl


# KDD 41维特征列（与原模型一致）
NETFLOW_FEATURE_COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]
LABEL_COL = 'label'

# -------------------------- 核心修复：CIC→KDD特征映射（增强鲁棒性） --------------------------
def cic_to_kdd_features(cic_df):
    """将CIC-DDoS2019数据集（列名带前置空格）映射为KDD 41维特征"""
    # 防御性拷贝：避免修改原数据
    cic_df = cic_df.copy()
    kdd_data = {}
    
    # -------------- 1. 基础时间/计数特征（适配CIC带空格列名） --------------
    # 流持续时间：CIC" Flow Duration"（毫秒）→ KDD"duration"（秒）
    flow_duration = cic_df.get(" Flow Duration", pd.Series([0]*len(cic_df)))  # 修复：统一为Series
    kdd_data['duration'] = flow_duration / 1000  # 毫秒转秒
    
    # 总流数：CIC前向+后向总包数 → KDD"count"
    fwd_pkts = cic_df.get(" Total Fwd Packets", pd.Series([0]*len(cic_df)))
    bwd_pkts = cic_df.get(" Total Backward Packets", pd.Series([0]*len(cic_df)))
    kdd_data['count'] = fwd_pkts + bwd_pkts  # 确保为数值型
    
    # -------------- 2. 协议类型映射（CIC" Protocol"列，带空格） --------------
    # 默认值改为空Series，避免长度不匹配
    proto_series = cic_df[" Protocol"] if " Protocol" in cic_df.columns else pd.Series([], dtype=int)
    proto_series = proto_series.fillna(0)  # 填充缺失值
    # 协议数值→字符串（6=TCP，17=UDP，1=ICMP，58=ICMPv6）
    proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6'}
    kdd_data['protocol_type'] = proto_series.map(proto_map).fillna('unknown')
    
    # -------------- 3. 服务类型映射（CIC" Destination Port"列，带空格） --------------
    dst_port_series = cic_df[" Destination Port"] if " Destination Port" in cic_df.columns else pd.Series([], dtype=int)
    dst_port_series = dst_port_series.fillna(0)  # 填充缺失值
    # 端口→服务名（覆盖CIC常见服务端口）
    port_service_map = {
        80: 'http', 443: 'https', 53: 'dns', 21: 'ftp', 22: 'ssh',
        389: 'ldap', 25: 'smtp', 110: 'pop3', 143: 'imap', 3389: 'telnet'
    }
    kdd_data['service'] = dst_port_series.map(port_service_map).fillna('unknown')
    
    # -------------- 4. TCP Flags计算（CIC无直接列，用6个标志列组合） --------------
    def calculate_tcp_flags(row):
        """根据CIC的6个标志列计算TCP Flags数值"""
        flags = 0
        # 标志位映射：FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
        if row.get(" FIN Flag Count", 0) >= 1:
            flags |= 0x01
        if row.get(" SYN Flag Count", 0) >= 1:
            flags |= 0x02
        if row.get(" RST Flag Count", 0) >= 1:
            flags |= 0x04
        if row.get(" PSH Flag Count", 0) >= 1:
            flags |= 0x08
        if row.get(" ACK Flag Count", 0) >= 1:
            flags |= 0x10
        if row.get(" URG Flag Count", 0) >= 1:
            flags |= 0x20
        return flags
    
    # 应用计算函数，得到TCP Flags数值
    cic_df['_calculated_tcp_flags'] = cic_df.apply(calculate_tcp_flags, axis=1)
    # TCP Flags数值→KDD flag标签
    tcp_flag_map = {
        0x12: 'SF',    # SYN+ACK（正常连接）
        0x02: 'SYN',   # 仅SYN（连接请求）
        0x04: 'RSTO',  # 仅RST（连接重置）
        0x14: 'REJ',   # RST+ACK（连接拒绝）
        0x08: 'PSH',   # 仅PSH（数据推送）
        0x01: 'FIN',   # 仅FIN（连接关闭）
        0x11: 'FIN_ACK'# FIN+ACK（关闭确认）
    }
    kdd_data['flag'] = cic_df['_calculated_tcp_flags'].map(tcp_flag_map).fillna('OTH')  # 未知状态设为OTH
    
    # -------------- 5. 字节数特征（CIC带空格列名） --------------
    # 前向字节数：CIC" Total Length of Fwd Packets" → KDD"src_bytes"
    kdd_data['src_bytes'] = cic_df.get(" Total Length of Fwd Packets", pd.Series([0]*len(cic_df)))
    # 后向字节数：CIC" Total Length of Bwd Packets" → KDD"dst_bytes"
    kdd_data['dst_bytes'] = cic_df.get(" Total Length of Bwd Packets", pd.Series([0]*len(cic_df)))
    
    # -------------- 6. 补全KDD其他缺失特征（无数据时填0，不影响模型） --------------
    for col in NETFLOW_FEATURE_COLUMNS:
        if col not in kdd_data:
            kdd_data[col] = pd.Series([0.0]*len(cic_df))  # 修复：统一用float0.0
    
    # -------------- 7. 清理临时列 + 格式转换 --------------
    cic_df.drop(columns=['_calculated_tcp_flags'], inplace=True)  # 新增：删除临时列，避免污染
    kdd_df = pd.DataFrame(kdd_data)[NETFLOW_FEATURE_COLUMNS]
    
    # 确保所有列都是数值型（除了字符串特征）
    for col in kdd_df.columns:
        if col in ['protocol_type', 'service', 'flag']:
            kdd_df[col] = kdd_df[col].astype(str)
        else:
            kdd_df[col] = pd.to_numeric(kdd_df[col], errors='coerce').fillna(0.0)
    
    return kdd_df

# -------------------------- 数据加载函数（增强容错） --------------------------
def load_data(dataset_type="merge"):
    logging.info(f"=== 加载{dataset_type}类型数据集 ===")
    train_data, test_data = None, None
    
    # -------------- 1. 加载KDD数据集 --------------
    if dataset_type in ["kdd", "merge"]:
        kdd_train_path = os.path.join(DATA_DIR, "KDDTrain+.csv")
        kdd_test_path = os.path.join(DATA_DIR, "KDDTest+.csv")
        
        if not os.path.exists(kdd_train_path) or not os.path.exists(kdd_test_path):
            raise FileNotFoundError(
                f"KDD数据集缺失！\n"
                f"请将KDDTrain+.csv和KDDTest+.csv放入 {DATA_DIR} 目录\n"
                f"当前检测到目录下文件：{os.listdir(DATA_DIR) if os.path.exists(DATA_DIR) else 'data目录不存在'}"
            )
        
        try:
            kdd_train = pd.read_csv(
                kdd_train_path,
                names=NETFLOW_FEATURE_COLUMNS + [LABEL_COL],
                low_memory=False,
                sep=",",
                skipinitialspace=True,
                header=None,
                usecols=range(42),
                skiprows=0
            )
            kdd_test = pd.read_csv(
                kdd_test_path,
                names=NETFLOW_FEATURE_COLUMNS + [LABEL_COL],
                low_memory=False,
                sep=",",
                skipinitialspace=True,
                header=None,
                usecols=range(42),
                skiprows=0
            )
            
            # KDD标签二值化→float类型（0.0/1.0）
            kdd_train[LABEL_COL] = kdd_train[LABEL_COL].apply(
                lambda x: 0.0 if str(x).strip() == 'normal' else 1.0
            )
            kdd_test[LABEL_COL] = kdd_test[LABEL_COL].apply(
                lambda x: 0.0 if str(x).strip() == 'normal' else 1.0
            )
            
            logger.info(f"KDD加载完成：训练集{len(kdd_train)}行，标签类型={kdd_train[LABEL_COL].dtype}")
            train_data, test_data = kdd_train, kdd_test
        except Exception as e:
            raise RuntimeError(f"KDD加载失败：{str(e)}")
    
    # -------------- 2. 加载CIC数据集 --------------
    if dataset_type in ["cic", "merge"]:
        cic_train_path = os.path.join(DATA_DIR, "CIC-DDoS2019_train.csv")
        cic_test_path = os.path.join(DATA_DIR, "CIC-DDoS2019_test.csv")
        
        if not os.path.exists(cic_train_path) or not os.path.exists(cic_test_path):
            raise FileNotFoundError(
                f"CIC合并文件缺失！\n"
                f"请先运行merge_cic.py生成CIC-DDoS2019_train.csv和CIC-DDoS2019_test.csv，放入 {DATA_DIR} 目录\n"
                f"当前检测到目录下文件：{os.listdir(DATA_DIR) if os.path.exists(DATA_DIR) else 'data目录不存在'}"
            )
        
        try:
            cic_train_raw = pd.read_csv(cic_train_path, encoding='utf-8', low_memory=False)
            cic_test_raw = pd.read_csv(cic_test_path, encoding='utf-8', low_memory=False)
            logger.info(f"CIC原始数据加载完成：训练集{len(cic_train_raw)}行，测试集{len(cic_test_raw)}行")
            
            # 特征映射
            cic_train = cic_to_kdd_features(cic_train_raw)
            cic_test = cic_to_kdd_features(cic_test_raw)
            
            # CIC标签二值化→float类型（0.0/1.0）
            def process_cic_label(label):
                return 0.0 if str(label).strip().upper() == 'BENIGN' else 1.0
            
            cic_train[LABEL_COL] = cic_train_raw[" Label"].apply(process_cic_label)
            cic_test[LABEL_COL] = cic_test_raw[" Label"].apply(process_cic_label)
            
            logging.info(f"CIC特征映射完成：训练集{len(cic_train)}行，标签类型={cic_train[LABEL_COL].dtype}")
            
            # 合并数据集
            if dataset_type == "merge":
                # 验证合并前类型
                assert train_data[LABEL_COL].dtype == 'float64', f"KDD标签类型错误，应为float64"
                assert cic_train[LABEL_COL].dtype == 'float64', f"CIC标签类型错误，应为float64"
                
                # 执行合并
                train_data = pd.concat([train_data, cic_train], ignore_index=True)
                test_data = pd.concat([test_data, cic_test], ignore_index=True)
                logger.info(f"合并后：训练集{len(train_data)}行，标签类型={train_data[LABEL_COL].dtype}")
            else:
                train_data, test_data = cic_train, cic_test
        except Exception as e:
            raise RuntimeError(f"CIC处理失败：{str(e)}")
    
    # -------------- 3. 最终验证（放宽浮点精度检查） --------------
    assert train_data[LABEL_COL].dtype == 'float64', f"训练集标签最终类型错误，应为float64"
    assert test_data[LABEL_COL].dtype == 'float64', f"测试集标签最终类型错误，应为float64"
    
    # 修复：允许浮点精度误差（比如0.0000001视为0.0）
    train_label_vals = train_data[LABEL_COL].round(6).unique()
    test_label_vals = test_data[LABEL_COL].round(6).unique()
    assert set(train_label_vals).issubset({0.0, 1.0}), f"训练集标签值异常：{train_label_vals}"
    assert set(test_label_vals).issubset({0.0, 1.0}), f"测试集标签值异常：{test_label_vals}"
    
    logging.info("数据集加载+类型验证通过")
    return train_data, test_data

# -------------------------- 数据预处理函数（兼容双数据集） --------------------------
def preprocess_data(train_data, test_data):
    logging.info("=== 开始数据预处理 ===")
    string_feature_cols = ['protocol_type', 'service', 'flag']
    feature_encoders = {}
    
    # 1. 编码字符串特征
    for col in string_feature_cols:
        # 合并训练+测试集时的缺失值处理
        combined_feature = pd.concat([train_data[col], test_data[col]], axis=0).fillna("unknown").astype(str)
        encoder = LabelEncoder()
        encoder.fit(combined_feature)
        train_data[col] = encoder.transform(train_data[col].fillna("unknown").astype(str))
        test_data[col] = encoder.transform(test_data[col].fillna("unknown").astype(str))
        feature_encoders[col] = encoder
        logger.info(f"完成{col}列编码：类别数={len(encoder.classes_)}")
    
    # 2. 数值特征强制转数值型
    for col in NETFLOW_FEATURE_COLUMNS:
        train_data[col] = pd.to_numeric(train_data[col], errors='coerce').fillna(0.0)
        test_data[col] = pd.to_numeric(test_data[col], errors='coerce').fillna(0.0)
    
    # 3. 验证标签
    logger.info(f"预处理后：训练集标签类型={train_data[LABEL_COL].dtype}，测试集标签类型={test_data[LABEL_COL].dtype}")
    train_label_vals = train_data[LABEL_COL].round(6).unique()
    test_label_vals = test_data[LABEL_COL].round(6).unique()
    assert set(train_label_vals).issubset({0.0, 1.0}), f"预处理后训练集标签值异常：{train_label_vals}"
    assert set(test_label_vals).issubset({0.0, 1.0}), f"预处理后测试集标签值异常：{test_label_vals}"
    
    # 4. 标准化数值特征（修复异常值）
    scaler = StandardScaler()
    #标准化前过滤无穷值/NaN
    X_train_raw = train_data[NETFLOW_FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_test_raw = test_data[NETFLOW_FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)
    
    # 5. 获取标签
    y_train = train_data[LABEL_COL].values
    y_test = test_data[LABEL_COL].values
    logger.info(f"标签数组类型：y_train={y_train.dtype}，y_test={y_test.dtype}")
    
    # 6. 保存预处理组件
    joblib.dump(feature_encoders, FEATURE_ENCODERS_PATH)
    joblib.dump(scaler, SCALER_PATH)
    logging.info("预处理完成：已保存特征编码器和标准化器")
    
    return X_train, X_test, y_train, y_test

# -------------------------- 模型训练函数（支持增量训练） --------------------------
def train_model(dataset_type="merge", incremental=False, n_estimators=100):
    """
    模型训练入口
    dataset_type: 数据集类型（kdd/cic/merge）
    incremental: 是否增量训练（加载已有模型继续训练）
    n_estimators: 随机森林决策树数量（默认100，增量训练时叠加）
    return: 训练是否成功（bool），评估指标（dict）
    """
    try:
        # 1. 加载数据
        train_data, test_data = load_data(dataset_type)
        
        # 2. 预处理数据
        X_train, X_test, y_train, y_test = preprocess_data(train_data, test_data)
        
        # 检查数据形状
        assert X_train.shape[0] == y_train.shape[0], f"训练集特征和标签行数不匹配：X={X_train.shape[0]}, y={y_train.shape[0]}"
        assert X_test.shape[0] == y_test.shape[0], f"测试集特征和标签行数不匹配：X={X_test.shape[0]}, y={y_test.shape[0]}"
        assert X_train.shape[1] == len(NETFLOW_FEATURE_COLUMNS), f"训练集特征列数错误：{X_train.shape[1]} != {len(NETFLOW_FEATURE_COLUMNS)}"
        
        # 3. 模型初始化（增量/全新）
        model_path = os.path.join(MODEL_DIR, f"{MODEL_PREFIX}{dataset_type}.pkl")
        if incremental and os.path.exists(model_path):
            # 增量训练：加载已有模型
            model = joblib.load(model_path)
            # 增量训练时校验参数
            new_n_estimators = model.n_estimators + n_estimators
            if new_n_estimators > 1000:  # 防止决策树过多导致内存溢出
                logger.warning(f"增量训练后决策树数量{new_n_estimators}过大，限制为1000")
                new_n_estimators = 1000
            model.n_estimators = new_n_estimators
            logger.info(f"加载已有模型：{model_path}，增量训练（总决策树数={model.n_estimators}）")
        else:
            # 全新训练：初始化随机森林
            model = RandomForestClassifier(
                n_estimators=n_estimators,
                random_state=42,
                n_jobs=-1,
                verbose=1,
                max_depth=20,  # 限制树深度，防止过拟合
                min_samples_split=5  # 防止过拟合
            )
            logger.info(f"全新训练{dataset_type}模型：决策树数量={n_estimators}")
        
        # 4. 训练模型
        logging.info("开始模型训练...")
        model.fit(X_train, y_train)
        logging.info("模型训练完成")
        
        # 5. 模型评估
        y_pred = model.predict(X_test)
        # 修复：处理标签全为0/1的情况（避免recall/precision报错）
        try:
            metrics = {
                "准确率": accuracy_score(y_test, y_pred),
                "召回率": recall_score(y_test, y_pred, zero_division=0),  # 零除法处理
                "精确率": precision_score(y_test, y_pred, zero_division=0)
            }
        except Exception as e:
            logger.warning(f"评估指标计算失败：{e}，仅返回准确率")
            metrics = {"准确率": accuracy_score(y_test, y_pred)}
        
        logging.info(f"=== 模型评估结果（{dataset_type}）===")
        for name, value in metrics.items():
            logging.info(f"{name}：{value:.4f}")
        
        # 6. 保存模型
        joblib.dump(model, model_path)
        logger.info(f"模型已保存：{model_path}")
        
        return True, metrics
    except Exception as e:
        logger.error(f"模型训练失败：{str(e)}", exc_info=True)
        return False, None

# -------------------------- 训练入口（可直接运行） --------------------------
if __name__ == "__main__":
    # 训练配置（可修改以下参数）
    TRAIN_CONFIG = {
        "dataset_type": "merge",    # 训练类型：kdd/cic/merge（推荐merge）
        "incremental": False,       # 是否增量训练（首次训练设为False）
        "n_estimators": 100         # 决策树数量（越多精度越高，推荐100-200）
    }
    
    logging.info("=== 启动NetFlow入侵检测模型训练 ===")
    logging.info(f"训练配置：{TRAIN_CONFIG}")
    logging.info(f"系统环境：{platform.system()} {platform.release()}")  # 打印系统信息
    
    # 执行训练
    success, metrics = train_model(
        dataset_type=TRAIN_CONFIG["dataset_type"],
        incremental=TRAIN_CONFIG["incremental"],
        n_estimators=TRAIN_CONFIG["n_estimators"]
    )
    
    # 输出最终结果
    if success:
        logging.info("=== 训练任务全部完成！ ===")
        logging.info(f"最终评估指标：{metrics}")
    else:
        logging.error("=== 训练任务失败，请查看logs/run_system.log排查问题 ===")