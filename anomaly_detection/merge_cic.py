#!/usr/bin/env python3
# -*- coding=utf-8 -*-
import pandas as pd
import os
import logging
from logging.handlers import RotatingFileHandler

# -------------------------- 修复：路径转义问题（避免SyntaxWarning） --------------------------
# 路径用 raw 字符串（前缀加 r），或把 \ 改成 \\
CIC_DATA_DIR = r"D:\BS\Dataset\CIC-DDoS2019\data"  # 加 r 表示原始字符串，无需转义
OUTPUT_DIR = "data"
TRAIN_SUFFIX = "training.csv"
TEST_SUFFIX = "testing.csv"

# -------------------------- 新增：日志同时输出到控制台和文件 --------------------------
def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # 避免重复添加处理器
    if logger.handlers:
        logger.handlers.clear()
    
    # 1. 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)
    
    # 2. 文件处理器（日志保存到 logs/merge_cic.log，最大10MB，保留3个备份）
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "merge_cic.log"),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'))
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logger()

# -------------------------- 核心合并逻辑（修复 read_csv 报错） --------------------------
def get_all_cic_files(data_dir, suffix):
    cic_files = []
    for root, dirs, files in os.walk(data_dir):
        for file in files:
            if file.endswith(suffix) and not file.startswith("._"):
                file_path = os.path.join(root, file)
                cic_files.append(file_path)
                logger.info(f"找到文件：{file_path}")
    return cic_files

def merge_cic_datasets():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 合并训练集
    train_files = get_all_cic_files(CIC_DATA_DIR, TRAIN_SUFFIX)
    if not train_files:
        logger.error(f"未找到任何训练文件（后缀：{TRAIN_SUFFIX}）")
        return False
    
    try:
        train_dfs = []
        for file in train_files:
            # 修复：pandas 2.3.3 无 errors 参数，用 on_bad_lines='skip' 跳过坏行
            df = pd.read_csv(file, encoding='utf-8', on_bad_lines='skip')
            train_dfs.append(df)
            logger.info(f"读取训练文件：{file}（行数：{len(df)}）")
        
        merged_train = pd.concat(train_dfs, ignore_index=True, axis=0)
        train_output_path = os.path.join(OUTPUT_DIR, "CIC-DDoS2019_train.csv")
        merged_train.to_csv(train_output_path, index=False, encoding='utf-8')
        logger.info(f"训练集合并完成！输出路径：{train_output_path}（总行数：{len(merged_train)}）")
    except Exception as e:
        logger.error(f"训练集合并失败：{str(e)}", exc_info=True)
        return False
    
    # 合并测试集
    test_files = get_all_cic_files(CIC_DATA_DIR, TEST_SUFFIX)
    if not test_files:
        logger.error(f"未找到任何测试文件（后缀：{TEST_SUFFIX}）")
        return False
    
    try:
        test_dfs = []
        for file in test_files:
            df = pd.read_csv(file, encoding='utf-8', on_bad_lines='skip')
            test_dfs.append(df)
            logger.info(f"读取测试文件：{file}（行数：{len(df)}）")
        
        merged_test = pd.concat(test_dfs, ignore_index=True, axis=0)
        test_output_path = os.path.join(OUTPUT_DIR, "CIC-DDoS2019_test.csv")
        merged_test.to_csv(test_output_path, index=False, encoding='utf-8')
        logger.info(f"测试集合并完成！输出路径：{test_output_path}（总行数：{len(merged_test)}）")
    except Exception as e:
        logger.error(f"测试集合并失败：{str(e)}", exc_info=True)
        return False
    
    return True

if __name__ == "__main__":
    logger.info("=== 开始合并CIC-DDoS2019数据集 ===")
    success = merge_cic_datasets()
    if success:
        logger.info("=== 数据集合并全部完成！ ===")
    else:
        logger.error("=== 数据集合并失败，请查看日志排查问题 ===")