from flask import Flask, request, jsonify, send_from_directory, Blueprint
from flask_cors import CORS
from datetime import datetime, timedelta
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
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row  # 让查询结果可以用row['字段名']访问
        return conn
    except sqlite3.Error as e:
        app.logger.error(f"数据库连接失败：{str(e)}")
        raise  # 抛出异常，让接口层捕获

def init_db_table():
    conn = get_db_connection()
    conn.commit()
    conn.close()
    print("数据库表重建完成，所有字段已正确配置")

# -------------------------- 核心：带/api前缀的接口路由 --------------------------
# 1. Top IP统计接口（前端请求：/api/stats_ip/total）
@app.route('/api/stats_ip/total', methods=['GET'])
def stats_ip_total():
    try:
        ip_type = request.args.get('type', 'src')
        limit = int(request.args.get('limit', 10))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if ip_type == 'src':
            # 补充SUM(in_packets)（总包数）、COUNT(*)（总流数）
            cursor.execute("""
                SELECT src_ip AS ip, 
                       SUM(in_bytes) AS total_bytes,
                       SUM(in_packets) AS total_packets,
                       COUNT(*) AS total_flows
                FROM netflow
                GROUP BY src_ip
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (limit,))
        else:
            cursor.execute("""
                SELECT dst_ip AS ip, 
                       SUM(in_bytes) AS total_bytes,
                       SUM(in_packets) AS total_packets,
                       COUNT(*) AS total_flows
                FROM netflow
                GROUP BY dst_ip
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        # 补充total_packets、total_flows字段
        data = [{
            'ip': row['ip'], 
            'total_bytes': row['total_bytes'],
            'total_packets': row['total_packets'],
            'total_flows': row['total_flows']
        } for row in results]
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# 2. 实时流量接口（前端请求：/api/realtime/flows）
@app.route('/api/realtime/flows', methods=['GET'])
def realtime_flows():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 补充in_packets（包数）、timestamp字段
        cursor.execute("""
            SELECT src_ip, dst_ip, protocol, src_port, dst_port, in_bytes, in_packets, timestamp
            FROM netflow
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        results = cursor.fetchall()
        conn.close()
        
        # 补充packets字段（匹配前端）
        data = [{'src_ip': row['src_ip'], 'dst_ip': row['dst_ip'], 
                 'protocol': row['protocol'], 'src_port': row['src_port'], 
                 'dst_port': row['dst_port'], 'bytes': row['in_bytes'],
                 'packets': row['in_packets']}  # 新增packets字段
                for row in results]
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# 3. IP历史趋势接口（前端请求：/api/stats_ip/date_history）
@app.route('/api/stats_ip/date_history', methods=['GET'])
def stats_ip_date_history():
    """
    获取TOP IP流量数据（真实NetFlow数据）
    支持参数：
    - top_n: 返回前N个IP（默认10）
    - hours: 统计最近N小时的数据（默认24，传0则统计所有）
    """
    try:
        # 适配前端传参：top_limit→top_n，days→hours（1天=24小时）
        top_n = int(request.args.get('top_limit', 10))  
        days = int(request.args.get('days', 1))
        hours = days * 24  # 转换天数为小时
        ip_type = request.args.get('type', 'src')  # 接收type参数
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # 修正：按IP类型（src/dst）统计，且返回按日期分组的history
        if ip_type == 'src':
            sql = """
                SELECT src_ip AS ip, DATE(timestamp) AS date, SUM(in_bytes) AS bytes
                FROM netflow
                WHERE timestamp >= ?
                GROUP BY src_ip, DATE(timestamp)
                ORDER BY bytes DESC
            """
        else:
            sql = """
                SELECT dst_ip AS ip, DATE(timestamp) AS date, SUM(in_bytes) AS bytes
                FROM netflow
                WHERE timestamp >= ?
                GROUP BY dst_ip, DATE(timestamp)
                ORDER BY bytes DESC
            """
        start_time = datetime.now() - timedelta(hours=hours)
        cursor.execute(sql, (start_time.strftime('%Y-%m-%d %H:%M:%S'),))
        results = cursor.fetchall()
        conn.close()

        # 重构数据结构：匹配前端期望的 {ip, history: [{date, bytes}]}
        ip_map = {}
        for row in results:
            ip = row['ip']
            if ip not in ip_map:
                ip_map[ip] = {'ip': ip, 'history': []}
            ip_map[ip]['history'].append({
                'date': row['date'],
                'bytes': row['bytes']
            })
        
        # 取TOP N IP
        real_data = sorted(ip_map.values(), key=lambda x: sum(h['bytes'] for h in x['history']), reverse=True)[:top_n]

        return jsonify({
            'success': True,
            'data': real_data,
            'count': len(real_data)
        }), 200

    except sqlite3.Error as e:
        app.logger.error(f"数据库查询失败：{str(e)}")
        return jsonify({
            'success': False,
            'error': f"数据库错误：{str(e)}",
            'data': []
        }), 500
    except ValueError as e:
        app.logger.error(f"参数错误：{str(e)}")
        return jsonify({
            'success': False,
            'error': f"参数错误：{str(e)}",
            'data': []
        }), 400
    except Exception as e:
        app.logger.error(f"接口未知错误：{str(e)}")
        return jsonify({
            'success': False,
            'error': f"服务器错误：{str(e)}",
            'data': []
        }), 500

# -------------------------- 启动服务 --------------------------
if __name__ == '__main__':
    # 初始化数据库表
    init_db_table()
    # 启动Flask服务（0.0.0.0允许局域网访问，端口8000）
    app.run(host='0.0.0.0', port=8000, debug=True)