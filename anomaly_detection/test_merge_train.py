#!/usr/bin/env python3
# -*- coding=utf-8 -*-
import pytest
import os
import pandas as pd
import joblib
from merge_cic import merge_cic_datasets
from model_train import load_data, preprocess_data, train_model, NETFLOW_FEATURE_COLUMNS, MODEL_DIR

# -------------------------- 测试配置 --------------------------
TEST_CIC_DIR = "test_cic_data"  # 测试用CIC迷你数据集目录
TEST_OUTPUT_DIR = "data"
MODEL_TYPE = "merge"

# -------------------------- 测试夹具（自动准备测试环境） --------------------------
@pytest.fixture(scope="module")
def prepare_test_cic_data():
    """创建迷你CIC测试数据集（模拟真实数据格式）"""
    # 创建测试目录
    os.makedirs(TEST_CIC_DIR, exist_ok=True)
    os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)
    
    # 生成迷你训练集
    train_data = pd.DataFrame({
        'Flow Duration': [1000, 2000, 3000],
        'Protocol': [6, 17, 1],
        'Destination Port': [80, 53, 21],
        'Total Length of Fwd Packets': [1024, 2048, 512],
        'Total Length of Bwd Packets': [512, 1024, 256],
        'TCP Flags': [0x12, 0x02, 0x04],
        'Label': ['BENIGN', 'DNS', 'FTP']
    })
    train_data.to_csv(os.path.join(TEST_CIC_DIR, "test_training.csv"), index=False)
    
    # 生成迷你测试集
    test_data = pd.DataFrame({
        'Flow Duration': [1500, 2500],
        'Protocol': [6, 17],
        'Destination Port': [443, 22],
        'Total Length of Fwd Packets': [1536, 2560],
        'Total Length of Bwd Packets': [768, 1280],
        'TCP Flags': [0x12, 0x08],
        'Label': ['BENIGN', 'SSH']
    })
    test_data.to_csv(os.path.join(TEST_CIC_DIR, "test_testing.csv"), index=False)
    
    yield  # 测试完成后清理
    # 删除测试文件
    for root, dirs, files in os.walk(TEST_CIC_DIR):
        for file in files:
            os.remove(os.path.join(root, file))
    os.rmdir(TEST_CIC_DIR)

# -------------------------- 核心测试用例 --------------------------
def test_merge_cic(prepare_test_cic_data, monkeypatch):
    """测试merge_cic.py的数据集合并功能"""
    # 替换配置项为测试路径
    monkeypatch.setattr("merge_cic.CIC_DATA_DIR", TEST_CIC_DIR)
    monkeypatch.setattr("merge_cic.TRAIN_SUFFIX", "training.csv")
    monkeypatch.setattr("merge_cic.TEST_SUFFIX", "testing.csv")
    
    # 运行合并
    success = merge_cic_datasets()
    assert success is True, "CIC数据集合并失败"
    
    # 验证合并文件存在
    train_output = os.path.join(TEST_OUTPUT_DIR, "CIC-DDoS2019_train.csv")
    test_output = os.path.join(TEST_OUTPUT_DIR, "CIC-DDoS2019_test.csv")
    assert os.path.exists(train_output), f"合并训练集未生成：{train_output}"
    assert os.path.exists(test_output), f"合并测试集未生成：{test_output}"
    
    # 验证数据格式
    train_df = pd.read_csv(train_output)
    test_df = pd.read_csv(test_output)
    assert len(train_df) == 3, f"合并训练集行数错误（预期3行，实际{len(train_df)}行）"
    assert len(test_df) == 2, f"合并测试集行数错误（预期2行，实际{len(test_df)}行）"
    print("✅ merge_cic.py测试通过！")

def test_run_system_load_data(test_merge_cic):
    """测试run_system.py的数据集加载功能"""
    # 加载合并数据集（kdd需提前放在data目录，或仅测试cic）
    try:
        train_data, test_data = load_data(dataset_type=MODEL_TYPE)
    except FileNotFoundError:
        # 若没有KDD数据集，测试cic类型
        train_data, test_data = load_data(dataset_type="cic")
    
    # 验证数据格式
    assert train_data.shape[1] == 42, f"训练集列数错误（预期42列，实际{train_data.shape[1]}列）"
    assert test_data.shape[1] == 42, f"测试集列数错误（预期42列，实际{test_data.shape[1]}列）"
    assert 'protocol_type' in train_data.columns, "缺失protocol_type特征列"
    assert 'label' in train_data.columns, "缺失label标签列"
    print("✅ run_system.py数据加载测试通过！")

def test_run_system_preprocess(test_run_system_load_data):
    """测试run_system.py的数据预处理功能"""
    # 加载数据
    try:
        train_data, test_data = load_data(dataset_type=MODEL_TYPE)
    except FileNotFoundError:
        train_data, test_data = load_data(dataset_type="cic")
    
    # 预处理
    X_train, X_test, y_train, y_test = preprocess_data(train_data, test_data)
    
    # 验证预处理结果
    assert X_train.shape[1] == len(NETFLOW_FEATURE_COLUMNS), f"特征维度错误（预期{len(NETFLOW_FEATURE_COLUMNS)}维，实际{X_train.shape[1]}维）"
    assert set(y_train) == {0, 1}, "标签二值化错误（应仅含0和1）"
    assert X_train.dtype == 'float64', "特征未标准化（应为float64类型）"
    print("✅ run_system.py数据预处理测试通过！")

def test_run_system_train_model(test_run_system_preprocess):
    """测试run_system.py的模型训练功能"""
    # 训练迷你模型（决策树数量设为10，加快测试）
    success = train_model(
        dataset_type=MODEL_TYPE,
        incremental=False,
        n_estimators=10
    )
    assert success is True, "模型训练失败"
    
    # 验证模型组件生成
    model_path = os.path.join(MODEL_DIR, f"netflow_model_{MODEL_TYPE}.pkl")
    encoder_path = os.path.join(MODEL_DIR, "feature_encoders.pkl")
    scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
    
    assert os.path.exists(model_path), f"模型文件未生成：{model_path}"
    assert os.path.exists(encoder_path), f"特征编码器未生成：{encoder_path}"
    assert os.path.exists(scaler_path), f"标准化器未生成：{scaler_path}"
    
    # 验证模型可加载
    model = joblib.load(model_path)
    assert hasattr(model, 'predict'), "模型文件损坏（无predict方法）"
    print("✅ run_system.py模型训练测试通过！")

if __name__ == "__main__":
    """直接运行脚本执行所有测试"""
    pytest.main([__file__, "-v", "--no-header"])
