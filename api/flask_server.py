
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask API适配器 - 连接collector_v9.py和mnet前端
基于mnet的API设计规范，适配SQLite数据源
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

# 数据库路径 - 指向项目根目录的netflow.db
DATABASE_PATH = '../netflow.db'

def get_db_connection():
    """连接SQLite数据库"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """初始化数据库表结构"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 创建netflow_records表（如果不存在）
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS netflow_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol INTEGER,
            packets INTEGER DEFAULT 0,
            bytes INTEGER DEFAULT 0,
            duration INTEGER DEFAULT 0,
            flags TEXT,
            tos INTEGER
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/api/stats_ip/total')
def stats_ip_total():
    """
    复用mnet的API接口：/api/stats_ip/total
    从SQLite读取数据，返回Top IP总流量统计
    """
    try:
        stat_type = request.args.get('type', 'src')
        limit = int(request.args.get('limit', 10))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if stat_type == 'src':
            query = '''
                SELECT 
                    src_ip as ip, 
                    SUM(bytes) as total_bytes,
                    SUM(packets) as total_packets,
                    COUNT(*) as total_flows
                FROM netflow_records 
                GROUP BY src_ip 
                ORDER BY total_bytes DESC 
                LIMIT ?
            '''
        else:
            query = '''
                SELECT 
                    dst_ip as ip,
                    SUM(bytes) as total_bytes,
                    SUM(packets) as total_packets,
                    COUNT(*) as total_flows
                FROM netflow_records 
                GROUP BY dst_ip 
                ORDER BY total_bytes DESC 
                LIMIT ?
            '''
        
        cursor.execute(query, (limit,))
        results = cursor.fetchall()
        
        # 转换为mnet期望的JSON格式
        stats =  []
        for row in results:
            stats.append({
                'ip': row['ip'],
                'total_bytes': row['total_bytes'],
                'total_packets': row['total_packets'],
                'total_flows': row['total_flows']
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'data': stats,
            'type': stat_type,
            'total_count': len(stats)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats_ip/date_history')
def stats_ip_date_history():
    """
    复用mnet的API接口：/api/stats_ip/date_history
    从SQLite读取IP流量历史数据（按时间分组）
    """
    try:
        stat_type = request.args.get('type', 'src')
        days = int(request.args.get('days', 7))
        top_limit = int(request.args.get('top_limit', 5))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 计算时间范围
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        if stat_type == 'src':
            # 先获取Top N源IP
            top_query = '''
                SELECT src_ip as ip, SUM(bytes) as total_bytes
                FROM netflow_records 
                WHERE timestamp >= ?
                GROUP BY src_ip 
                ORDER BY total_bytes DESC 
                LIMIT ?
            '''
            
            # 再获取这些IP的历史数据
            history_query = '''
                SELECT 
                    DATE(timestamp) as date,
                    src_ip as ip,
                    SUM(bytes) as bytes,
                    SUM(packets) as packets,
                    COUNT(*) as flows
                FROM netflow_records 
                WHERE src_ip IN ({}) AND timestamp >= ?
                GROUP BY DATE(timestamp), src_ip
                ORDER BY date, ip
            '''
        else:
            # 目标IP查询
            top_query = '''
                SELECT dst_ip as ip, SUM(bytes) as total_bytes
                FROM netflow_records 
                WHERE timestamp >= ?
                GROUP BY dst_ip 
                ORDER BY total_bytes DESC 
                LIMIT ?
            '''
            
            history_query = '''
                SELECT 
                    DATE(timestamp) as date,
                    dst_ip as ip,
                    SUM(bytes) as bytes,
                    SUM(packets) as packets,
                    COUNT(*) as flows
                FROM netflow_records 
                WHERE dst_ip IN ({}) AND timestamp >= ?
                GROUP BY DATE(timestamp), dst_ip
                ORDER BY date, ip
            '''
        
        # 获取Top IP
        cursor.execute(top_query, (start_date, top_limit))
        top_ips = [row['ip'] for row in cursor.fetchall()]
        
        if not top_ips:
            conn.close()
            return jsonify({
                'success': True,
                'data': [],
                'message': 'No data found'
            })
        
        # 获取历史数据
        placeholders = ','.join(['?' for _ in top_ips])
        cursor.execute(history_query.format(placeholders), (*top_ips, start_date))
        history_results = cursor.fetchall()
        
        # 组织数据为mnet期望的格式
        history_data = {}
        for row in history_results:
            ip = row['ip']
            if ip not in history_data:
                history_data[ip] = {
                    'ip': ip,
                    'history': []              
                                    }
            
            history_data[ip]['history'].append({
                'date': row['date'],
                'bytes': row['bytes'],
                'packets': row['packets'],
                'flows': row['flows']
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'data': list(history_data.values()),
            'date_range': {
                'start': start_date.strftime('%Y-%m-%d'),
                'end': end_date.strftime('%Y-%m-%d')
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/realtime/flows')
def realtime_flows():
    """
    复用mnet的API接口：/api/realtime/flows
    返回实时流数据（最近1小时）
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        one_hour_ago = datetime.now() - timedelta(hours=1)
        
        cursor.execute('''
            SELECT 
                src_ip, dst_ip, src_port, dst_port,
                protocol, packets, bytes, duration, timestamp
            FROM netflow_records 
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT 100
        ''', (one_hour_ago,))
        
        flows = []       
        for row in cursor.fetchall():
            flows.append({
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'src_port': row['src_port'],
                'dst_port': row['dst_port'],
                'protocol': row['protocol'],
                'packets': row['packets'],
                'bytes': row['bytes'],
                'duration': row['duration'],
                'timestamp': row['timestamp']
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'data': flows,
            'count': len(flows),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/add_flow', methods=['POST'])
def add_flow():
    """
    添加NetFlow记录 - 你的collector_v9.py可以调用这个接口
    或者collector_v9.py继续直接写入SQLite，这个接口可选
    """
    try:
        data = request.get_json()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO netflow_records 
            (src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, duration, flags, tos)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('src_ip'),
            data.get('dst_ip'),
            data.get('src_port'),
            data.get('dst_port'),
            data.get('protocol'),
            data.get('packets', 0),
            data.get('bytes', 0),
            data.get('duration', 0),
            data.get('flags'),
            data.get('tos')
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Flow record added successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/health')
def health_check():
    """健康检查接口"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM netflow_records')
        record_count = cursor.fetchone()[0]
        conn.close()
        
        return jsonify({
            'success': True,
            'database': 'connected',
            'record_count': record_count,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'database': 'error',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # 初始化数据库
    init_database()
    
    # 启动Flask服务器
    app.run(
        host='0.0.0.0', 
        port=8000, 
        debug=True
    )
    
    print("🚀 Flask API适配器已启动")
    print("📊 API接口列表:")
    print("  - GET /api/stats_ip/total?type=src")
    print("  - GET /api/stats_ip/date_history?type=src")
    print("  - GET /api/realtime/flows")
    print("  - POST /api/add_flow")
    print("  - GET /api/health")