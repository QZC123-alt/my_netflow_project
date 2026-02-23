#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全局日志工具：仅保留【模块独立日志+全局错误日志+控制台输出】，无总日志
核心功能：1.各模块日志写入专属文件 2.全局错误日志汇总 3.日志自动轮转 4.控制台实时输出
"""
import os
import logging
from logging.handlers import RotatingFileHandler
import sys

# ===================== 1. 导入/兜底配置（适配你的config.py）=====================
try:
    from config import LOG_CONFIG, PROJECT_ROOT
    # 模块-日志文件映射（贴合你的实际模块）
    MODULE_LOG_MAP = {
        "main": "main.log",                # 主程序
        "collector_v9": "collector_v9.log",# 流量采集
        "flow_processor": "flow_processor.log",# 流量处理+异常检测
        "flask_server": "flask.log",       # Flask后端
        "anomaly_routes": "flask.log",     # 后端路由（归到flask日志）
        "model_train": "model_train.log"   # 模型训练
    }
    GLOBAL_ERROR_LOG = "error.log"  # 全局错误日志
except ImportError:
    # 极端兜底配置（若config.py导入失败）
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    LOG_CONFIG = {
        "level": "DEBUG",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
        "datefmt": "%Y-%m-%d %H:%M:%S",
        "log_dir": "logs",
        "max_bytes": 10 * 1024 * 1024,
        "backup_count": 5,
        "console_output": True
    }
    MODULE_LOG_MAP = {
        "main": "main.log",
        "collector_v9": "collector_v9.log",
        "flow_processor": "flow_processor.log",
        "flask_server": "flask.log",
        "anomaly_routes": "flask.log",
        "model_train": "model_train.log"
    }
    GLOBAL_ERROR_LOG = "error.log"

# ===================== 2. 初始化日志目录=====================
LOG_DIR = os.path.join(PROJECT_ROOT, LOG_CONFIG["log_dir"])
os.makedirs(LOG_DIR, exist_ok=True)  # 自动创建logs文件夹

# ===================== 3. 日志基础配置=====================
LOG_LEVEL = getattr(logging, LOG_CONFIG["level"].upper(), logging.DEBUG)
LOG_FORMAT = logging.Formatter(
    fmt=LOG_CONFIG["format"],
    datefmt=LOG_CONFIG["datefmt"]
)
ROTATE_MAX_BYTES = LOG_CONFIG["max_bytes"]  # 单个日志最大10MB
ROTATE_BACKUP_COUNT = LOG_CONFIG["backup_count"]  # 保留5个备份
CONSOLE_OUTPUT = LOG_CONFIG["console_output"]  # 是否开启控制台输出


# ===================== 4. 模块专属日志核心函数（无总日志）=====================
def get_module_logger(module_name):
    """
    获取模块专属logger：日志写入【模块独立文件+全局错误日志】，同时输出到控制台
    :param module_name: 模块名（如main/collector_v9）
    :return: 配置好的logger实例
    """
    # 创建模块专属logger，关闭传播避免重复输出
    logger = logging.getLogger(module_name)
    logger.setLevel(LOG_LEVEL)
    logger.propagate = False

    # 4.1 控制台输出（实时看日志）
    if CONSOLE_OUTPUT:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(LOG_FORMAT)
        # 避免重复添加控制台处理器
        if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
            logger.addHandler(console_handler)

    # 4.2 模块独立日志文件（每个模块写自己的文件）
    if module_name in MODULE_LOG_MAP:
        log_file = os.path.join(LOG_DIR, MODULE_LOG_MAP[module_name])
        # 检查是否已有该文件的处理器
        has_file_handler = False
        for handler in logger.handlers:
            if isinstance(handler, RotatingFileHandler) and handler.baseFilename == log_file:
                has_file_handler = True
                break
        # 没有则添加
        if not has_file_handler:
            file_handler = RotatingFileHandler(
                filename=log_file,
                mode='a',
                maxBytes=ROTATE_MAX_BYTES,
                backupCount=ROTATE_BACKUP_COUNT,
                encoding="utf-8"
            )
            file_handler.setFormatter(LOG_FORMAT)
            logger.addHandler(file_handler)

    # 4.3 全局错误日志（所有模块的ERROR级日志汇总到error.log）
    error_log_file = os.path.join(LOG_DIR, GLOBAL_ERROR_LOG)
    # 检查是否已有错误日志处理器
    has_error_handler = False
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler) and handler.baseFilename == error_log_file:
            has_error_handler = True
            break
    # 没有则添加（只记录ERROR及以上级别）
    if not has_error_handler:
        error_handler = RotatingFileHandler(
            filename=error_log_file,
            mode='a',
            maxBytes=ROTATE_MAX_BYTES,
            backupCount=ROTATE_BACKUP_COUNT,
            encoding="utf-8"
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(LOG_FORMAT)
        logger.addHandler(error_handler)

    return logger