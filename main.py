#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import time
import sys
import os
import socketserver
import logging
import webbrowser  # 新增：用于自动打开浏览器

# 添加项目路径
sys.path.append(os.path.dirname(__file__))
from config import NETFLOW_CONFIG, MONITOR_CONFIG, WEB_CONFIG
from utils.log_utils import get_module_logger
logger = get_module_logger("main")  # 日志文件

def start_packet_capture():
    """
    启动NetFlow v9收集服务（生产级版本）
    特性：多线程处理、线程安全模板缓存、全量异常捕获、端口复用
    """
    try:
        # 1. 导入核心依赖
        from data_collection.collector_v9 import (
            createdb, ExportPacket, batch_write_netflow, FLOW_CACHE, BATCH_WRITE_THRESHOLD
        )
        import socketserver
        import logging
        import os
        import threading


        # 3. 初始化数据库
        logging.info("[收集服务] 初始化NetFlow数据库...")
        createdb()

        # 4. 多线程UDP服务器（解决单线程阻塞/崩溃问题）
        class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
            allow_reuse_address = True  # 端口复用，避免重启报错
            daemon_threads = True       # 守护线程，主进程退出时自动结束

        # 5. 全局模板缓存（所有线程共享，线程安全）
        GLOBAL_TEMPLATES = {}
        TEMPLATE_LOCK = threading.Lock()

        # 6. NetFlow UDP处理器（生产级逻辑）
        class NetFlowUDPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                """
                单包处理逻辑（每个请求一个线程）
                流程：接收数据 → 解析报文 → 更新模板 → 写入缓存 → 日志输出
                """
                # 基础信息
                client_addr = self.client_address
                data, _ = self.request
                logging.info(f"\n[收集服务] 收到来自 {client_addr} 的包 | 长度：{len(data)}字节")

                try:
                    # 线程安全地访问全局模板缓存
                    with TEMPLATE_LOCK:
                        # 解析NetFlow v9报文
                        export_packet = ExportPacket(data, GLOBAL_TEMPLATES)
                        # 模板缓存已通过export_packet.templates自动更新，无需额外操作

                    # 写入流数据到缓存（线程安全）
                    for flow in export_packet.flows:
                        batch_write_netflow(flow)

                    # 控制台友好输出（演示/监控用）
                    if len(export_packet.flows) > 0:
                        print(f"📥 收到{client_addr[0]} | 解析{len(export_packet.flows)}条流 | 缓存待写入{len(FLOW_CACHE)}条")
                    else:
                        with TEMPLATE_LOCK:
                            print(f"📋 收到{client_addr[0]} | 模板报文 | 已缓存{len(GLOBAL_TEMPLATES)}个模板")

                # 捕获所有异常，避免单个包解析失败导致线程崩溃
                except Exception as e:
                    logger.error(f"[处理失败] 客户端{client_addr}：{str(e)}", exc_info=True)
                    print(f"❌ 处理{client_addr[0]}数据失败：{str(e)}")

        # 7. 启动UDP服务器
        HOST = NETFLOW_CONFIG["host"]
        PORT = NETFLOW_CONFIG["port"]  # 真实端口，不再硬编码
        logger.info(f"[收集服务] 启动多线程UDP服务器 | {HOST}:{PORT}")
        
        # 启动服务器（阻塞式，需在子线程中运行）
        server = ThreadedUDPServer((HOST, PORT), NetFlowUDPHandler)
        server.serve_forever()

    except ImportError as e:
        logger.error(f"[收集服务] 依赖导入失败：{str(e)} | 请检查collector_v9.py路径是否正确")
        print(f"❌ 依赖导入失败：{str(e)}")
    except OSError as e:
        logger.error(f"[收集服务] 端口占用失败：{str(e)} | 请检查{PORT}端口是否被占用（可执行 netstat -ano | findstr :{PORT}）")
        print(f"❌ 端口占用失败：{str(e)}")
    except Exception as e:
        logger.error(f"[收集服务] 启动失败：{str(e)}", exc_info=True)
        print(f"❌ 收集服务启动失败：{str(e)}")

def start_anomaly_detection():
    """启动异常检测（来自ai-network-anomaly）
    from anomaly_detection.simple_detector import start_detection_service
    print("启动异常检测...")
    start_detection_service()"""

    """启动数据处理和异常检测"""
    try:
        from data_integration.flow_processor import FlowProcessor
        
        print("启动数据处理器...")
        processor = FlowProcessor()
        processor.start_processing()
        
    except Exception as e:
        print(f"启动数据处理器失败: {e}")

# 假设监控函数在main.py中，名为monitor_system
def monitor_system():
    """修复版：实时查询数据库，显示流记录总数"""
    import sqlite3
    import time
    # ========== 核心修复1：确保数据库路径与Collector写入的路径一致 ==========
    # 从collector_v9.py中复用DB_PATH，避免路径不一致
    from data_collection.collector_v9 import DB_PATH
    
    while True:
        try:
            # 每次查询都重新连接数据库（避免缓存）
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            # ========== 核心修复2：确保查询语句正确（表名与你的表一致） ==========
            cursor.execute("SELECT COUNT(*) FROM netflow;")  # 表名必须是你实际的表名
            flowcount = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM anomaly_records;")  # 表名必须是你实际的表名
            anocount = cursor.fetchone()[0]
            conn.close()
            
            # 更新显示（覆盖原有输出）
            logger.info(f"\r📊 流记录总数：{flowcount} | ⚠️ 异常记录：{anocount}")
        except Exception as e:
            logger.info(f"\r📊 流记录总数：查询失败 | 错误：{str(e)}", end="")
        time.sleep(MONITOR_CONFIG["interval"])  # 每30秒刷新（与监控显示的“每30秒更新统计”对应）

def start_web_interface():
    """启动Web界面"""
    print("启动Web界面...")
    try:
        from api.flask_server import app, init_db_table
        init_db_table()
        
        # 新增：构造Web访问地址（从配置中读取host和port，适配你的配置）
        web_url = f"http://localhost:{WEB_CONFIG['port']}" 
        # 新增：延迟1秒（确保Web服务先启动，避免浏览器先弹出来但页面无法访问）
        def open_browser_auto():
            time.sleep(1)
            webbrowser.open(web_url)  # 调用系统默认浏览器打开地址
        
        # 新增：启动子线程执行自动打开浏览器（不阻塞Web服务启动）
        threading.Thread(target=open_browser_auto, daemon=True).start()
        
        # 原有打印提示保留，方便查看
        print(f"Web服务器启动成功！已自动打开浏览器，访问地址：{web_url}")
        app.run(
            host=WEB_CONFIG["host"],
            port=WEB_CONFIG["port"],
            debug=WEB_CONFIG["debug"],
            use_reloader=False
        )
    except Exception as e:
        print(f"启动Web界面失败: {e}")

def main():
    """主函数"""
    print("启动网络流量分析系统...")
    print("=" * 50)
    

        # 1. 初始化数据库表
    try:
        from api.flask_server import init_db_table
        print("初始化数据库表...")
        init_db_table()
        print("数据库表初始化完成！")
    except Exception as e:
        print(f"数据库表初始化失败: {e}")
        return
    
    # 2. 新增：写入系统启动时间到model_config表（修复运行时长显示）
    try:
        from api.flask_server import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        start_time_ts = int(time.time())  # 当前时间戳（秒）
        cursor.execute("""
            INSERT OR REPLACE INTO model_config (param_name, param_value, description)
            VALUES ('start_time', ?, '系统启动时间戳（秒）')
        """, (start_time_ts,))
        conn.commit()
        conn.close()
        print(f"系统启动时间已写入model_config表（时间戳：{start_time_ts}）")
    except Exception as e:
        print(f"写入系统启动时间失败：{e}")


    # 创建线程
    threads = []
    # 数据包捕获线程
    capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
    threads.append(capture_thread)
    
    # 异常检测线程  
    detection_thread = threading.Thread(target=start_anomaly_detection, daemon=True)
    threads.append(detection_thread)
    
    # 监控显示线程
    monitor_thread = threading.Thread(target=monitor_system, daemon=True)
    threads.append(monitor_thread)

    # Web界面线程
    web_thread = threading.Thread(target=start_web_interface, daemon=True)
    threads.append(web_thread)
    
    # 启动所有线程
    for thread in threads:
        thread.start()
        time.sleep(1)
    
    print("所有服务已启动！")
    print("NetFlow服务器监听端口: 9995")
    print("Web界面: http://localhost:8000")
    print("监控显示: 每30秒更新统计")
    print("按 Ctrl+C 退出")
    print("=" * 50)

    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("正在关闭系统...")

if __name__ == "__main__":
    main()