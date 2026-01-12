from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os

# 初始化Flask应用
app = Flask(__name__)
CORS(app)
# 数据库配置（根据你的实际路径修改，确保路径正确）
DATABASE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),  # 项目根目录（当前文件的上一级）
    'netflow.db'  # 数据库文件名
)

# -------------------------- 数据库工具函数 --------------------------
def get_db_connection():
    """获取数据库连接，自动适配字段名访问"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # 让查询结果可以用row['字段名']访问
    return conn

def init_db_table():
    """初始化netflow_records表（不存在则创建）"""
    if not os.path.exists(DATABASE_PATH):
        conn = get_db_connection()
        cursor = conn.cursor()
        # 创建NetFlow记录表结构
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
        print("数据库表初始化成功！")

# -------------------------- 核心：带/api前缀的接口路由 --------------------------
# 1. Top IP统计接口（前端请求：/api/stats_ip/total）
@app.route('/api/stats_ip/total', methods=['GET'])
def stats_ip_total():
    """
    获取Top源/目标IP统计
    参数：type=src/dst（默认src），limit=返回条数（默认10）
    """
    try:
        # 获取并验证参数
        stat_type = request.args.get('type', 'src')
        limit = request.args.get('limit', 10)
        
        if stat_type not in ['src', 'dst']:
            return jsonify({'success': False, 'error': "type只能是src或dst"}), 400
        try:
            limit = int(limit)
            if limit <= 0:
                raise ValueError
        except ValueError:
            return jsonify({'success': False, 'error': "limit必须是正整数"}), 400

        # 拼接查询字段（src_ip/dst_ip）
        ip_field = 'src_ip' if stat_type == 'src' else 'dst_ip'
        conn = get_db_connection()
        cursor = conn.cursor()

        # 按IP分组统计字节数、包数、流数
        sql = f"""
            SELECT 
                {ip_field} as ip,
                SUM(bytes) as total_bytes,
                SUM(packets) as total_packets,
                COUNT(*) as total_flows
            FROM netflow_records
            GROUP BY {ip_field}
            ORDER BY total_bytes DESC
            LIMIT ?
        """
        cursor.execute(sql, (limit,))
        results = cursor.fetchall()
        conn.close()

        # 格式化返回数据（适配前端表格）
        data = []
        for row in results:
            data.append({
                'ip': row['ip'],
                'total_bytes': row['total_bytes'],
                'total_packets': row['total_packets'],
                'total_flows': row['total_flows']
            })

        return jsonify({'success': True, 'data': data}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': f"服务器错误：{str(e)}"}), 500

# 2. 实时流量接口（前端请求：/api/realtime/flows）
@app.route('/api/realtime/flows', methods=['GET'])
def realtime_flows():
    """获取实时流数据（适配前端统计总流量/包数等）"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 查询所有流数据（可加时间过滤，比如近10分钟）
        cursor.execute("""
            SELECT src_ip, dst_ip, protocol, packets, bytes 
            FROM netflow_records
            ORDER BY timestamp DESC
            LIMIT 1000
        """)
        results = cursor.fetchall()
        conn.close()

        # 格式化数据
        data = []
        for row in results:
            data.append({
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'protocol': row['protocol'],
                'packets': row['packets'],
                'bytes': row['bytes']
            })

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