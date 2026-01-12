from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os

app = Flask(__name__)
CORS(app)

# -------------------------- 核心修改：定位到web/public文件夹 --------------------------
# 1. 获取项目根目录：
# - __file__ → api/flask_server.py
# - os.path.dirname(__file__) → api文件夹
# - os.path.dirname(os.path.dirname(__file__)) → 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))

# 2. 前端文件路径：项目根目录 → web → public
FRONTEND_DIR = os.path.join(PROJECT_ROOT, 'web', 'public')

# -------------------------- 托管前端的路由（不用改） --------------------------
# 访问前端文件（如index.html、静态资源）
@app.route('/<path:filename>')
def serve_frontend(filename):
    return send_from_directory(FRONTEND_DIR, filename)

# 访问根路径时返回index.html
@app.route('/')
def index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

# 数据库配置（根据你的实际路径修改，确保路径正确）
DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'netflow.db')

# -------------------------- 数据库工具函数 --------------------------
def get_db_connection():
    """获取数据库连接，自动适配字段名访问"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # 让查询结果可以用row['字段名']访问
    return conn

def init_db_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    
    conn.commit()
    conn.close()
    print("数据库表重建完成，所有字段已正确配置")

# -------------------------- 核心：带/api前缀的接口路由 --------------------------
# 1. Top IP统计接口（前端请求：/api/stats_ip/total）
@app.route('/api/stats_ip/total', methods=['GET'])
def stats_ip_total():
    try:
        # 获取请求参数（type=src或dst）
        ip_type = request.args.get('type', 'src')
        limit = int(request.args.get('limit', 10))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 修正：表名是netflow，字段是src_ip/dst_ip + in_bytes
        if ip_type == 'src':
            # 按源IP分组，统计入向字节数总和
            cursor.execute("""
                SELECT src_ip AS ip, SUM(in_bytes) AS total_bytes
                FROM netflow
                GROUP BY src_ip
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (limit,))
        else:
            # 按目标IP分组，统计入向字节数总和
            cursor.execute("""
                SELECT dst_ip AS ip, SUM(in_bytes) AS total_bytes
                FROM netflow
                GROUP BY dst_ip
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        # 格式化返回数据（匹配前端所需结构）
        data = [{'ip': row['ip'], 'total_bytes': row['total_bytes']} for row in results]
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# 2. 实时流量接口（前端请求：/api/realtime/flows）
@app.route('/api/realtime/flows', methods=['GET'])
def realtime_flows():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 修正：表名netflow，字段匹配实际结构
        cursor.execute("""
            SELECT src_ip, dst_ip, protocol, src_port, dst_port, in_bytes
            FROM netflow
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        results = cursor.fetchall()
        conn.close()
        
        data = [{'src_ip': row['src_ip'], 'dst_ip': row['dst_ip'], 
                 'protocol': row['protocol'], 'src_port': row['src_port'], 
                 'dst_port': row['dst_port'], 'bytes': row['in_bytes']} 
                for row in results]
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# 3. IP历史趋势接口（前端请求：/api/stats_ip/date_history）
@app.route('/api/stats_ip/date_history', methods=['GET'])
def stats_ip_history():
    """获取Top IP的历史流量趋势（适配前端图表）"""
    try:
        # 模拟数据（你可根据实际需求修改SQL查询真实历史）
        data = [
            {
                "ip": "192.168.1.100",
                "history": [
                    {"date": "2026-01-07", "bytes": 102400},
                    {"date": "2026-01-08", "bytes": 204800},
                    {"date": "2026-01-09", "bytes": 153600},
                    {"date": "2026-01-10", "bytes": 256000},
                    {"date": "2026-01-11", "bytes": 184320}
                ]
            },
            {
                "ip": "192.168.1.101",
                "history": [
                    {"date": "2026-01-07", "bytes": 81920},
                    {"date": "2026-01-08", "bytes": 122880},
                    {"date": "2026-01-09", "bytes": 92160},
                    {"date": "2026-01-10", "bytes": 143360},
                    {"date": "2026-01-11", "bytes": 102400}
                ]
            }
        ]
        return jsonify({'success': True, 'data': data}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------- 启动服务 --------------------------
if __name__ == '__main__':
    # 初始化数据库表
    init_db_table()
    # 启动Flask服务（0.0.0.0允许局域网访问，端口8000）
    app.run(host='0.0.0.0', port=8000, debug=True)