
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库调试脚本
检查数据库和API连接
"""

import sqlite3
import requests
import os

def check_database():
    """检查数据库状态"""
    
    db_path = 'netflow.db'
    
    print("🔍 检查数据库状态...")
    print("=" * 40)
    
    # 检查文件是否存在
    if not os.path.exists(db_path):
        print(f"❌ 数据库文件不存在: {db_path}")
        return False
    
    print(f"✅ 数据库文件存在: {db_path}")
    
    # 检查文件大小
    file_size = os.path.getsize(db_path)
    print(f"📊 文件大小: {file_size} bytes")
    
    try:
        # 连接数据库
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 检查表是否存在
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print(f"📋 数据库表: {[table[0] for table in tables]}")
        
        if ('netflow',) in tables:
            # 检查记录数
            cursor.execute("SELECT COUNT(*) FROM netflow")
            count = cursor.fetchone()[0]
            print(f"📊 netflow表记录数: {count}")
            
            # 检查最近几条记录
            if count > 0:
                cursor.execute("SELECT * FROM netflow ORDER BY id DESC LIMIT 3")
                records = cursor.fetchall()
                print("📝 最近3条记录:")
                for record in records:
                    print(f"   ID: {record[0]}, 源IP: {record[2]}, 目标IP: {record[3]}, 字节数: {record[8]}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ 数据库访问错误: {e}")
        return False

def check_api():
    """检查API服务器"""
    
    print("\n🌐 检查API服务器...")
    print("=" * 40)
    
    try:
        # 健康检查
        health_response = requests.get('http://127.0.0.1:8000/api/health', timeout=5)
        
        if health_response.status_code == 200:
            health_data = health_response.json()
            print("✅ API健康检查通过")
            print(f"📊 API返回记录数: {health_data.get('record_count', 0)}")
        else:
            print(f"❌ API健康检查失败: {health_response.status_code}")
            return False
        
        # 测试统计数据接口
        stats_response = requests.get('http://127.0.0.1:8000/api/stats_ip/total?type=src&limit=5', timeout=5)
        
        if stats_response.status_code == 200:
            stats_data = stats_response.json()
            print("✅ 统计接口正常")
            if stats_data.get('success') and stats_data.get('data'):
                print("📊 Top 5 源IP:")
                for i, ip_data in enumerate(stats_data['data'][:3]):
                    print(f"   {i+1}. {ip_data['ip']}: {ip_data['total_bytes']} bytes")
            else:
                print("📊 暂无统计数据")
        else:
            print(f"❌ 统计接口失败: {stats_response.status_code}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ API连接错误: {e}")
        return False

def check_frontend():
    """检查前端连接"""
    
    print("\n🖥️ 检查前端连接...")
    print("=" * 40)
    
    try:
        # 测试前端API调用
        response = requests.get('http://127.0.0.1:8000/api/health', timeout=5)
        
        if response.status_code == 200:
            print("✅ 前端可以访问API")
            print("💡 前端应该可以正常显示数据")
        else:
            print(f"❌ 前端API访问失败: {response.status_code}")
        
    except Exception as e:
        print(f"❌ 前端连接测试失败: {e}")

def main():
    """主函数"""
    print("🔍 NetFlow系统诊断工具")
    print("=" * 50)
    
    db_ok = check_database()
    api_ok = check_api()
    
    if db_ok and api_ok:
        check_frontend()
        
        print("\n🎉 系统状态良好！")
        print("💡 如果前端仍无数据，请:")
        print("   1. 运行 python test_data_generator.py 生成数据")
        print("   2. 刷新浏览器页面")
        print("   3. 检查浏览器控制台是否有错误")
    else:
        print("\n❌ 发现问题，请按上述提示修复")

if __name__ == '__main__':
    main()