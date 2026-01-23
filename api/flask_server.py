from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import os
import csv
from io import StringIO
from flask import make_response
from api.anomaly_routes import anomaly_bp
import time  

from data_integration.flow_processor import FlowProcessor  # 导入FlowProcessor类

from utils.log_utils import get_module_logger
logger = get_module_logger("flask_server")  # 日志文件

# 创建Flask应用
app = Flask(__name__)
CORS(app)

# 注册蓝图
app.register_blueprint(anomaly_bp)

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
    """初始化必要表：netflow(补字段) + anomaly_records + blocked_ips + model_config"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. 补全netflow表的is_processed字段（已有逻辑保留）
        cursor.execute("PRAGMA table_info(netflow);")
        columns = [col[1] for col in cursor.fetchall()]
        if 'is_processed' not in columns:
            cursor.execute("ALTER TABLE netflow ADD COLUMN is_processed INTEGER DEFAULT 0;")
            logger.info(f"已为netflow表添加is_processed字段")

        # 2. 补全anomaly_records表的is_false字段（已有逻辑保留）
        cursor.execute("PRAGMA table_info(anomaly_records);")
        anomaly_columns = [col[1] for col in cursor.fetchall()]
        if "is_false" not in anomaly_columns:
            cursor.execute("ALTER TABLE anomaly_records ADD COLUMN is_false INTEGER DEFAULT 0;")

        # 3. 创建blocked_ips表（阻断IP记录）
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                block_time INTEGER NOT NULL,
                UNIQUE(ip)
            )
        """)

        # 4. 创建model_config表（模型参数配置，无冗余）
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS model_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                param_name TEXT NOT NULL UNIQUE,
                param_value REAL NOT NULL,
                description TEXT,
                update_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
        """)

        # 插入默认模型参数（首次启动自动填充）
        default_params = [
            ("base_threshold", 0.4, "异常概率基准阈值（动态阈值的基础）"),
            ("block_threshold", 0.8, "高风险阻断阈值（超过则自动阻断IP）"),
            ("check_interval", 5, "检测间隔（秒）"),
            ("batch_size", 100, "批次处理大小（一次处理多少条流量）"),
            ("keep_days", 7, "数据保留天数（清理旧数据）"),
            ("alert_cache_threshold", 20, "异常缓存告警阈值")
        ]
        for name, value, desc in default_params:
            cursor.execute("""
                INSERT OR IGNORE INTO model_config (param_name, param_value, description)
                VALUES (?, ?, ?)
            """, (name, value, desc))

        conn.commit()
        conn.close()
        logger.info("初始化完成：4张核心表（netflow补字段+anomaly_records+blocked_ips+model_config）")
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
                SELECT src_ip AS ip, DATE(timestamp, 'unixepoch') AS date, SUM(in_bytes) AS bytes
                FROM netflow
            """
        else:
            base_sql = """
                SELECT dst_ip AS ip, DATE(timestamp, 'unixepoch') AS date, SUM(in_bytes) AS bytes
                FROM netflow
            """
        
        # 添加时间条件（hours=0时不限制）
        params = []
        if hours > 0:
            base_sql += " WHERE timestamp >= ?"
            start_time = datetime.now() - timedelta(hours=hours)
            start_time_ts = int(start_time.timestamp())  # 转为整数时间戳（如1716205800）
            params.append(start_time_ts)  # 传入整数参数，匹配表中timestamp字段类型
        
        base_sql += " GROUP BY ip, DATE(timestamp, 'unixepoch') ORDER BY bytes DESC"
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

# 4.导出 
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

# 新增：导出异常记录数据（专门适配anomaly.html）
@app.route('/api/export/anomaly_data', methods=['GET'])
def export_anomaly_data():
    """导出anomaly_records表的所有异常记录"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 查询所有异常记录（按时间倒序）
        cursor.execute("""
            SELECT 
                id, flow_id, src_ip, dst_ip, 
                in_bytes, out_bytes, in_packets, out_packets,
                anomaly_score, timestamp
            FROM anomaly_records
            ORDER BY timestamp DESC
        """)
        results = cursor.fetchall()
        conn.close()
        
        # 准备CSV数据（字段和anomaly.html表格对齐）
        output = StringIO()
        writer = csv.writer(output)
        # 写入CSV标题（和表格列名一致）
        writer.writerow([
            '异常ID', '关联流量ID', '源IP', '目的IP',
            '入字节', '出字节', '入包数', '出包数',
            '异常概率', '发生时间'
        ])
        
        # 写入数据（格式化时间戳）
        for row in results:
            writer.writerow([
                row['id'],
                row['flow_id'],
                row['src_ip'],
                row['dst_ip'],
                row['in_bytes'],
                row['out_bytes'],
                row['in_packets'],
                row['out_packets'],
                round(row['anomaly_score'], 4),  # 保留4位小数
                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row['timestamp']))  # 时间格式化
            ])
        
        # 构建响应（修复导出文件类型问题，和之前的导出接口一致）
        response = make_response(output.getvalue().encode('utf-8-sig'))  # UTF-8 BOM兼容Excel
        response.headers["Content-Disposition"] = "attachment; filename=anomaly_records.csv"
        response.headers["Content-Type"] = "text/csv; charset=utf-8"  # 明确文件类型
        return response
        
    except Exception as e:
        app.logger.error(f"导出异常数据错误：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# 新增：获取所有异常记录
@app.route('/api/anomaly/all', methods=['GET'])
def get_all_anomalies():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, flow_id, src_ip, dst_ip, in_bytes, out_bytes, anomaly_score, timestamp
            FROM anomaly_records
            ORDER BY timestamp DESC
        """)
        results = cursor.fetchall()
        conn.close()
        data = [{k: row[k] for k in row.keys()} for row in results]
        return jsonify({'success': True, 'data': data}), 200
    except Exception as e:
        app.logger.error(f"获取所有异常失败：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# 新增：按IP筛选异常记录
@app.route('/api/anomaly/recent', methods=['GET'])
def get_recent_anomalies():
    try:
        limit = int(request.args.get('limit', 5))
        filter_ip = request.args.get('ip', '').strip()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        sql = """
            SELECT id, flow_id, src_ip, dst_ip,in_bytes, anomaly_score, timestamp
            FROM anomaly_records
        """
        params = []
        if filter_ip:
            sql += " WHERE src_ip = ? OR dst_ip = ?"
            params.extend([filter_ip, filter_ip])
        
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(sql, params)
        results = cursor.fetchall()
        
        # 获取总数（支持筛选）
        total_sql = "SELECT COUNT(*) FROM anomaly_records"
        if filter_ip:
            total_sql += " WHERE src_ip = ? OR dst_ip = ?"
            total_cursor = conn.cursor()
            total_cursor.execute(total_sql, [filter_ip, filter_ip])
            total = total_cursor.fetchone()[0]
        else:
            total_cursor = conn.cursor()
            total_cursor.execute(total_sql)
            total = total_cursor.fetchone()[0]
        
        conn.close()
        data = [{
            'id': row['id'], 'flow_id': row['flow_id'], 'src_ip': row['src_ip'],
            'dst_ip': row['dst_ip'],'in_bytes': row['in_bytes'] ,'anomaly_score': row['anomaly_score'],
            'timestamp': row['timestamp']
        } for row in results]
        return jsonify({'success': True, 'data': data, 'total': total}), 200
    except Exception as e:
        app.logger.error(f"获取最近异常失败：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/anomaly/mark_false', methods=['POST'])
def mark_false():
    data = request.get_json()
    anomaly_id = data.get("anomaly_id")
    src_ip = data.get("src_ip")
    
    conn = sqlite3.connect("netflow.db")
    cursor = conn.cursor()
    # 1. 标记为误报（is_false=1）
    cursor.execute("UPDATE anomaly_records SET is_false=1 WHERE id=?", (anomaly_id,))
    # 2. 解除IP阻断
    processor = FlowProcessor()
    processor.unblock_ip_via_router(src_ip)
    
    conn.commit()
    conn.close()
    return jsonify({"success": True})

# ========== 系统配置接口 ==========
@app.route('/api/system/config', methods=['GET'])
def get_system_config():
    """获取系统配置（从数据库/配置文件读）"""
    config = {
        "highRiskThreshold": 0.8,
        "midRiskThreshold": 0.6,
        "refreshInterval": 30
    }
    return jsonify({"success": True, "data": config})

@app.route('/api/system/config', methods=['POST'])
def save_system_config():
    """保存系统配置（写到数据库/配置文件）"""
    data = request.get_json()
    # 实际项目中要把data存到数据库或config.ini
    return jsonify({"success": True, "msg": "配置保存成功"})

# ========== 系统状态接口 ==========
@app.route('/api/system/status', methods=['GET'])
def get_system_status():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. 统计今日异常数
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("""
            SELECT COUNT(*) as todayAnomalyCount 
            FROM anomaly_records 
            WHERE DATE(timestamp, 'unixepoch') = ?
        """, (today,))
        today_anomaly = cursor.fetchone()['todayAnomalyCount']

        # 2. 统计阻断IP数
        cursor.execute("SELECT COUNT(*) as blockedIpCount FROM blocked_ips")
        blocked_ips = cursor.fetchone()['blockedIpCount']

        # 3. 统计数据库大小（新增：更实用）
        cursor.execute("PRAGMA page_count")
        page_count = cursor.fetchone()[0]
        cursor.execute("PRAGMA page_size")
        page_size = cursor.fetchone()[0]
        db_size = page_count * page_size  # 数据库总字节数

        conn.close()

        # 4. 计算系统运行时长（模拟：实际可存启动时间到model_config）
        run_time = "3小时45分"  # 若需真实值，可在main.py启动时记录时间戳到表中

        return jsonify({
            "success": True,
            "data": {
                "runTime": run_time,
                "blockedIpCount": blocked_ips,
                "todayAnomalyCount": today_anomaly,
                "dbSize": db_size  # 新增：数据库容量
            }
        }), 200
    except Exception as e:
        app.logger.error(f"获取系统状态失败：{str(e)}")
        return jsonify({
            "success": False,
            "error": str(e),
            "data": {}
        }), 500



# ========== 阻断IP接口 ==========
@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    conn = get_db_connection()
    cursor = conn.cursor()
    # 假设你有blocked_ips表，存储真实阻断记录
    cursor.execute("""
        SELECT ip, reason, block_time as blockTime 
        FROM blocked_ips 
        ORDER BY block_time DESC
    """)
    results = cursor.fetchall()
    conn.close()
    # 转成前端需要的格式
    ips = [{k: row[k] for k in row.keys()} for row in results]
    return jsonify({"success": True, "data": ips})

# 手动阻断IP（同步路由器+写表）
@app.route('/api/blocked-ips', methods=['POST'])
def add_blocked_ip():
    try:
        data = request.get_json()
        ip = data.get('ip')
        reason = data.get('reason', '手动阻断')
        
        if not ip:
            return jsonify({"success": False, "error": "缺少IP地址"}), 400
        
        # 调用FlowProcessor的阻断方法（同步路由器+写表）
        processor = FlowProcessor()
        processor.block_ip_via_router(ip)
        
        return jsonify({"success": True, "msg": f"IP {ip} 阻断成功（同步路由器）"}), 200
    except Exception as e:
        app.logger.error(f"手动阻断IP失败：{str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

# 解除阻断IP（同步路由器+删表）
@app.route('/api/blocked-ips/<string:ip>', methods=['DELETE'])
def unblock_ip(ip):
    try:
        # 调用FlowProcessor的解除方法（同步路由器+删表）
        processor = FlowProcessor()
        processor.unblock_ip_via_router(ip)
        
        return jsonify({"success": True, "msg": f"IP {ip} 解除成功（同步路由器）"}), 200
    except Exception as e:
        app.logger.error(f"解除阻断IP失败：{str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


# 获取模型参数（给管理页面用）
@app.route('/api/model/config', methods=['GET'])
def get_model_config():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT param_name, param_value, description FROM model_config")
        results = cursor.fetchall()
        conn.close()
        # 转成前端需要的格式
        config = {}
        for row in results:
            config[row['param_name']] = row['param_value']
        return jsonify({"success": True, "data": config}), 200
    except Exception as e:
        app.logger.error(f"获取模型参数失败：{str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

# 保存模型参数（给管理页面用）
@app.route('/api/model/config', methods=['POST'])
def save_model_config():
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        # 更新参数（循环更新所有传过来的参数）
        for param_name, param_value in data.items():
            cursor.execute("""
                UPDATE model_config 
                SET param_value = ?, update_time = strftime('%s', 'now') 
                WHERE param_name = ?
            """, (param_value, param_name))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "msg": "参数保存成功，重启系统生效"}), 200
    except Exception as e:
        app.logger.error(f"保存模型参数失败：{str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

# -------------------------- 启动服务 --------------------------
if __name__ == '__main__':
    # 初始化数据库表
    init_db_table()
    # 启动Flask服务（0.0.0.0允许局域网访问，端口8000）
    app.run(host='0.0.0.0', port=8000, debug=True)