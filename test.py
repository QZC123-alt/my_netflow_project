#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetFlow测试数据生成器
用于快速填充数据库，验证仪表板功能
"""
import sqlite3
import os
import requests
import random
import time
from datetime import datetime, timedelta

def generate_realistic_flows():
    """生成真实的NetFlow数据"""
    
    # 真实的网络服务端口
    services = {
        80: 'HTTP',
        443: 'HTTPS', 
        22: 'SSH',
        21: 'FTP',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8080: 'Tomcat',
        3000: 'Node.js',
        3389: 'RDP',
        5900: 'VNC'
    }
    
    # 生成测试流数据
    flows =    base_time = datetime.now() - timedelta(days=7)
    
    print("🚀 开始生成NetFlow测试数据...")
    
    for i in range(500):  # 生成500条测试数据
        # 随机选择源IP和目标IP
        src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # 随机选择服务
        port = random.choice(list(services.keys()))
        
        # 根据服务类型生成不同大小的流量
        if services[port] in ['HTTP', 'HTTPS']:
            bytes_sent = random.randint(1024, 102400)  # 1KB-100KB
            packets = random.randint(10, 200)
        elif services[port] in ['MySQL', 'PostgreSQL']:
            bytes_sent = random.randint(512, 10240)  # 512B-10KB
            packets = random.randint(5, 50)
        elif services[port] in ['SSH', 'RDP', 'VNC']:
            bytes_sent = random.randint(2048, 51200)  # 2KB-50KB
            packets = random.randint(20, 100)
        else:
            bytes_sent = random.randint(256, 5120)  # 其他服务
            packets = random.randint(5, 25)
        
        flow_data = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),  # 随机源端口
            'dst_port': port,
            'protocol': random.choice([6, 17]),  # TCP/UDP
            'packets': packets,
            'bytes': bytes_sent,
            'duration': random.randint(1, 300),  # 连接持续时间(秒)
            'flags': '',
            'tos': 0
        }
        
        flows.append(flow_data)
        
        # 每生成50条显示进度
        if (i + 1) % 50 == 0:
            print(f"✅ 已生成 {i + 1}/500 条测试数据")
    
    return flows
def setup_database():
    """创建并初始化数据库"""
    
    # 数据库文件路径
    db_path = 'netflow.db'
    
    # 确保数据库文件存在
    if not os.path.exists(db_path):
        print("📁 创建数据库文件...")
        
        # 创建数据库和表
        with open('sql/create_tables.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.executescript(sql_script)
        conn.commit()
        conn.close()
        
        print("✅ 数据库创建完成")
    else:
        print("✅ 数据库文件已存在")
    
    return db_path


def send_flows_to_api(flows, batch_size=20):
    """批量发送流数据到API"""
    
    api_url = 'http://127.0.0.1:8000/api/add_flow'
    success_count = 0
    error_count = 0
    
    print(f"\n📡 开始发送数据到API (批次大小: {batch_size})...")
    
    for i in range(0, len(flows), batch_size):
        batch = flows[i:i + batch_size]
        
        for flow in batch:
            try:
                response = requests.post(api_url, json=flow, timeout=5)
                if response.status_code == 200:
                    success_count += 1
                else:
                    error_count += 1
                    print(f"❌ 发送失败: {response.status_code}")
            except Exception as e:
                error_count += 1
                print(f"❌ 发送错误: {e}")
        
        # 显示进度
        current_batch = min(i + batch_size, len(flows))
        print(f"📊 进度: {current_batch}/{len(flows)} (成功: {success_count}, 失败: {error_count})")
        
        # 避免请求过快
        time.sleep(0.1)
    
    print(f"\n🎉 数据发送完成!")
    print(f"✅ 成功: {success_count} 条")
    print(f"❌ 失败: {error_count} 条")
    
    return success_count, error_count

def create_time_distributed_data():
    """创建时间分布的测试数据（用于历史趋势图）"""
    
    print("\n📈 创建时间分布的测试数据...")
    
    # 模拟7天的数据，每天有不同的流量模式
    flows =    base_time = datetime.now() - timedelta(days=7)
    
    # 模拟几个主要IP的持续流量
    main_ips = [
        '192.168.1.100',
        '192.168.1.101', 
        '192.168.1.102',
        '192.168.1.103',
        '192.168.1.104'
    ]
    
    for day in range(7):
        current_day = base_time + timedelta(days=day)
        
        for ip in main_ips:
            # 每个主要IP每天生成10-30条记录
            daily_flows = random.randint(10, 30)
            
            for _ in range(daily_flows):
                # 模拟业务时间的高峰期
                hour = random.choices(
                    range(24),
                    weights=[0.5, 0.3, 0.3, 0.3, 0.5, 0.8, 1.2, 2.0, 2.5, 3.0, 3.2, 3.0,
                            2.8, 2.5, 2.2, 2.0, 2.5, 3.0, 3.5, 3.8, 3.2, 2.5, 1.5, 1.0]
                )[0]
                
                flow_time = current_day.replace(
                    hour=hour,
                    minute=random.randint(0, 59),
                    second=random.randint(0, 59)
                )
                
                flow_data = {
                    'src_ip': ip,
                    'dst_ip': f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([80, 443, 22, 3306, 8080]),
                    'protocol': random.choice([6, 17]),
                    'packets': random.randint(10, 100),
                    'bytes': random.randint(1024, 50000),
                    'duration': random.randint(1, 120),
                    'flags': '',
                    'tos': 0
                }
                
                flows.append(flow_data)
    
    return flows

def main():
    """主函数"""
    print("🌊 NetFlow测试数据生成器")
    print("=" * 50)
    
    # 先设置数据库
    db_path = setup_database()
    
    # 检查API服务器
    print("🔍 检查API服务器...")
    try:
        health_response = requests.get('http://127.0.0.1:8000/api/realtime/flows', timeout=5)
        if health_response.status_code == 200:
            print("✅ API服务器正常运行")
        else:
            print("❌ API服务器响应异常")
            return
    except Exception as e:
        print(f"❌ 无法连接API服务器: {e}")
        print("💡 请确保运行: cd api && python flask_server.py")
        return

if __name__ == '__main__':
    main()