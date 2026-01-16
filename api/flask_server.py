from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import os
import csv
from io import StringIO
from flask import make_response

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
# 确保前端目录存在
os.makedirs(FRONTEND_DIR, exist_ok=True)

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
DATABASE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)))
DATABASE_PATH = os.path.join(DATABASE_DIR, 'netflow.db')
# 确保数据库目录存在
os.makedirs(DATABASE_DIR, exist_ok=True)

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
    """初始化netflow表，确保表结构存在"""
    try:
        conn = get_db_connection()
      
        conn.commit()
        conn.close()
     
    except sqlite3.Error as e:
        app.logger.error(f"初始化数据库表失败：{str(e)}")
        raise

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
        app.logger.error(f"stats_ip_total接口错误：{str(e)}")
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
        app.logger.error(f"realtime_flows接口错误：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# 3. IP历史趋势接口（前端请求：/api/stats_ip/date_history）
@app.route('/api/stats_ip/date_history', methods=['GET'])
def stats_ip_date_history():
    """
    获取TOP IP流量数据（真实NetFlow数据）
    支持参数：
    - top_n: 返回前N个IP（默认10）
    - hours: 统计最近N小时的数据（默认24，传0则统计所有）
    - type: src/dst（默认src）
    """
    try:
        # 适配前端传参：top_limit→top_n，days→hours（1天=24小时）
        top_n = int(request.args.get('top_n', request.args.get('top_limit', 10)))
        hours = int(request.args.get('hours', request.args.get('days', 1) * 24))
        ip_type = request.args.get('type', 'src')  # 接收type参数
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # 修正：按IP类型（src/dst）统计，且返回按日期分组的history
        # 处理hours=0的情况（统计所有数据）
        if ip_type == 'src':
            base_sql = """
                SELECT src_ip AS ip, DATE(timestamp) AS date, SUM(in_bytes) AS bytes
                FROM netflow
            """
        else:
            base_sql = """
                SELECT dst_ip AS ip, DATE(timestamp) AS date, SUM(in_bytes) AS bytes
                FROM netflow
            """
        
        # 添加时间条件（hours=0时不限制）
        params = []
        if hours > 0:
            base_sql += " WHERE timestamp >= ?"
            start_time = datetime.now() - timedelta(hours=hours)
            params.append(start_time.strftime('%Y-%m-%d %H:%M:%S'))
        
        base_sql += " GROUP BY ip, DATE(timestamp) ORDER BY bytes DESC"
        cursor.execute(base_sql, params)
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
        real_data = sorted(ip_map.values(), 
                          key=lambda x: sum(h['bytes'] for h in x['history']), 
                          reverse=True)[:top_n]

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

@app.route('/api/export/all_stats', methods=['GET'])
def export_all_stats():
    """导出所有统计数据"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 查询总流量统计
        cursor.execute("""
            SELECT 
                COUNT(*) as total_flows,
                SUM(in_bytes) as total_bytes,
                SUM(in_packets) as total_packets,
                COUNT(DISTINCT src_ip) as unique_src_ips,
                COUNT(DISTINCT dst_ip) as unique_dst_ips
            FROM netflow
        """)
        total_stats = cursor.fetchone()
        
        # 准备CSV数据
        output = StringIO()
        writer = csv.writer(output)
        
        # 写入标题
        writer.writerow(['统计项', '数值'])
        
        # 写入数据
        writer.writerow(['总流数', total_stats['total_flows']])
        writer.writerow(['总字节数', total_stats['total_bytes']])
        writer.writerow(['总包数', total_stats['total_packets']])
        writer.writerow(['源IP数', total_stats['unique_src_ips']])
        writer.writerow(['目标IP数', total_stats['unique_dst_ips']])
        
        conn.close()
        
        # 构建响应
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=all_stats.csv"
        response.headers["Content-type"] = "text/csv"
        return response
        
    except Exception as e:
        app.logger.error(f"导出统计数据错误：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/export/top_ips', methods=['GET'])
def export_top_ips():
    """导出Top IP数据"""
    try:
        ip_type = request.args.get('type', 'src')
        limit = int(request.args.get('limit', 10))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if ip_type == 'src':
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
        
        # 准备CSV数据
        output = StringIO()
        writer = csv.writer(output)
        
        # 写入标题
        writer.writerow(['排名', 'IP地址', '总字节数', '总包数', '总流数'])
        
        # 写入数据
        for i, row in enumerate(results, 1):
            writer.writerow([
                i,
                row['ip'],
                row['total_bytes'],
                row['total_packets'],
                row['total_flows']
            ])
        
        # 构建响应
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=top_{ip_type}_ips.csv"
        response.headers["Content-type"] = "text/csv"
        return response
        
    except Exception as e:
        app.logger.error(f"导出Top IP数据错误：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/export/trend_data', methods=['GET'])
def export_trend_data():
    """导出流量趋势数据"""
    try:
        top_n = int(request.args.get('top_n', 5))
        hours = int(request.args.get('hours', 168))
        ip_type = request.args.get('type', 'src')
        
        conn = get_db_connection()
        cursor = conn.cursor()

        if ip_type == 'src':
            base_sql = """
                SELECT src_ip AS ip, DATE(timestamp) AS date, SUM(in_bytes) AS bytes
                FROM netflow
            """
        else:
            base_sql = """
                SELECT dst_ip AS ip, DATE(timestamp) AS date, SUM(in_bytes) AS bytes
                FROM netflow
            """
        
        params = []
        if hours > 0:
            base_sql += " WHERE timestamp >= ?"
            start_time = datetime.now() - timedelta(hours=hours)
            params.append(start_time.strftime('%Y-%m-%d %H:%M:%S'))
        
        base_sql += " GROUP BY ip, DATE(timestamp) ORDER BY bytes DESC"
        cursor.execute(base_sql, params)
        results = cursor.fetchall()
        conn.close()

        # 准备CSV数据
        output = StringIO()
        writer = csv.writer(output)
        
        # 获取所有唯一日期和IP
        dates = sorted(list(set(row['date'] for row in results)))
        ips = list(set(row['ip'] for row in results))[:top_n]  # 取前N个IP
        
        # 写入标题行
        header = ['日期'] + ips
        writer.writerow(header)
        
        # 写入数据行
        for date in dates:
            row_data = [date]
            for ip in ips:
                # 查找该IP在该日期的流量
                value = next((r['bytes'] for r in results if r['ip'] == ip and r['date'] == date), 0)
                row_data.append(value)
            writer.writerow(row_data)
        
        # 构建响应
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=trend_data.csv"
        response.headers["Content-type"] = "text/csv"
        return response
        
    except Exception as e:
        app.logger.error(f"导出趋势数据错误：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/export/protocol_data', methods=['GET'])
def export_protocol_data():
    """导出协议分布数据"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 查询协议统计
        cursor.execute("""
            SELECT protocol, 
                   COUNT(*) AS total_flows,
                   SUM(in_bytes) AS total_bytes,
                   SUM(in_packets) AS total_packets
            FROM netflow
            GROUP BY protocol
            ORDER BY total_bytes DESC
        """)
        results = cursor.fetchall()
        conn.close()
        
        # 协议名称映射
        protocol_names = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            58: 'ICMPv6'
        }
        
        # 准备CSV数据
        output = StringIO()
        writer = csv.writer(output)
        
        # 写入标题
        writer.writerow(['协议ID', '协议名称', '总流数', '总字节数', '总包数'])
        
        # 写入数据
        for row in results:
            writer.writerow([
                row['protocol'],
                protocol_names.get(row['protocol'], f'未知协议({row["protocol"]})'),
                row['total_flows'],
                row['total_bytes'],
                row['total_packets']
            ])
        
        # 构建响应
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=protocol_data.csv"
        response.headers["Content-type"] = "text/csv"
        return response
        
    except Exception as e:
        app.logger.error(f"导出协议数据错误：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------- 启动服务 --------------------------
if __name__ == '__main__':
    # 初始化数据库表
    init_db_table()
    # 启动Flask服务（0.0.0.0允许局域网访问，端口8000）
    app.run(host='0.0.0.0', port=8000, debug=True)