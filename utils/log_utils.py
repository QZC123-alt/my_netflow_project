import logging
from logging.handlers import RotatingFileHandler
import sys
import os

def get_module_logger(module_name):
    # 自动创建logs文件夹（如果不存在）
    os.makedirs("logs", exist_ok=True)

    # 其他代码不变，只修改filename为："logs/{module_name}.log"
    file_handler = RotatingFileHandler(
        filename=f"logs/{module_name}.log",  # 日志文件输出到logs文件夹
        maxBytes=50 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )

    # 1. 定义日志格式（时间+模块+级别+文件名+行号+内容）
    log_format = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 2. 创建日志对象（以模块名为标识）
    logger = logging.getLogger(module_name)
    logger.setLevel(logging.DEBUG)  # 全局日志级别
    logger.propagate = False  # 避免重复输出

    # 3. 控制台处理器（只输出INFO及以上）
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    console_handler.setLevel(logging.INFO)

    # 4. 文件处理器（输出到模块对应的日志文件，自动切割）
    file_handler = RotatingFileHandler(
        filename=f"{module_name}.log",  # 日志文件名=模块名.log
        maxBytes=50 * 1024 * 1024,  # 单个文件最大50MB
        backupCount=5,  # 最多保留5个备份
        encoding="utf-8"
    )
    file_handler.setFormatter(log_format)
    file_handler.setLevel(logging.DEBUG)  # 文件保留所有级别日志

    # 5. 绑定处理器到日志对象
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger