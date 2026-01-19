from flask import Blueprint, request, jsonify
import os
import sys
import joblib
import pandas as pd
import subprocess

# ========== 路径配置（与run_system.py统一） ==========
# 当前脚本所在目录（api）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 项目根目录
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
# 训练脚本路径
TRAIN_SCRIPT_PATH = os.path.join(PROJECT_ROOT, "anomaly_detection", "run_system.py")
# 模型组件路径（与run_system.py完全一致）
MODEL_PATH = os.path.join(MODEL_DIR, "netflow_model.pkl")
FEATURE_ENCODERS_PATH = os.path.join(MODEL_DIR, "feature_encoders.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
# ========== NetFlow特征列名（和训练时的run_system.py一致） ==========
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

# 创建蓝图
anomaly_bp = Blueprint("anomaly", __name__, url_prefix="/api/anomaly")


def load_only_feature_components():
    """仅加载【特征编码器+模型+标准化器】，无任何标签相关内容"""
    # 校验组件是否存在
    required_files = [MODEL_PATH, FEATURE_ENCODERS_PATH, SCALER_PATH]
    missing = [f for f in required_files if not os.path.exists(f)]
    if missing:
        raise Exception(f"缺失组件: {', '.join(missing)}")
    
    # 加载特征编码器（仅处理protocol_type/service/flag）
    feature_encoders = joblib.load(FEATURE_ENCODERS_PATH)
    assert set(feature_encoders.keys()) == {'protocol_type', 'service', 'flag'}, "特征编码器错误"
    
    return {
        "model": joblib.load(MODEL_PATH),
        "feature_encoders": feature_encoders,
        "scaler": joblib.load(SCALER_PATH)
    }

@anomaly_bp.route("/health", methods=["GET"])
def health_check():
    """服务健康检查"""
    return jsonify({
        "success": True,
        "service": "anomaly_detection_api",
        "status": "healthy"
    }), 200


@anomaly_bp.route('/status', methods=['GET'])
def model_status():
    """简化模型状态检查（只看核心组件）"""
    required = [
        ("模型", MODEL_PATH),
        ("特征编码器", FEATURE_ENCODERS_PATH),
        ("标准化器", SCALER_PATH)
    ]
    missing = [name for name, path in required if not os.path.exists(path)]
    if not missing:
        return jsonify({
            "success": True,
            "status": "model_ready",
            "message": "核心组件齐全"
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": f"缺少核心组件：{', '.join(missing)}"
        }), 400

@anomaly_bp.route("/train", methods=["POST"])
def train_model_api():
    """训练模型接口"""
    try:
        # 检查训练脚本是否存在
        if not os.path.exists(TRAIN_SCRIPT_PATH):
            return jsonify({
                "success": False,
                "error": f"训练脚本不存在：{TRAIN_SCRIPT_PATH}"
            }), 404

        # 调用训练脚本（自动选择训练选项）
        print("正在调用训练脚本...")
        result = subprocess.run(
            [sys.executable, TRAIN_SCRIPT_PATH],
            capture_output=True,
            text=True,
            input="1\n",  # 自动输入“1”选择训练
            cwd=os.path.dirname(TRAIN_SCRIPT_PATH)  # 工作目录设为训练脚本所在目录
        )

        # 处理训练结果
        if result.returncode == 0:
            return jsonify({
                "success": True,
                "message": "模型训练完成",
                "train_log": result.stdout.strip()
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": "训练失败",
                "train_log": result.stderr.strip()
            }), 500

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"训练接口异常：{str(e)}"
        }), 500


@anomaly_bp.route('/detect', methods=['POST'])
def detect_anomaly():
    try:
        # 1. 加载纯特征组件
        components = load_only_feature_components()
        
        # 2. 获取请求特征
        data = request.get_json()
        if not data or "features" not in data:
            return jsonify({"success": False, "error": "缺少'features'字段"}), 400
        features = data["features"]
        if len(features) != len(NETFLOW_FEATURE_COLUMNS):
            return jsonify({"success": False, "error": f"需{len(NETFLOW_FEATURE_COLUMNS)}个特征"}), 400
        
        # 3. 仅处理特征列（用特征编码器，无标签逻辑）
        feature_df = pd.DataFrame([features], columns=NETFLOW_FEATURE_COLUMNS)
        # 只处理3个特征字符串列，不碰任何标签
        for col in ['protocol_type', 'service', 'flag']:
            feature_df[col] = components["feature_encoders"][col].transform(feature_df[col].fillna("unknown"))
        
        # 4. 标准化+检测
        feature_scaled = components["scaler"].transform(feature_df)
        pred = components["model"].predict(feature_scaled)[0]
        
        return jsonify({
            "success": True,
            "is_anomaly": bool(pred == 1),
            "anomaly_flag": int(pred)
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"检测失败: {str(e)}"}), 500