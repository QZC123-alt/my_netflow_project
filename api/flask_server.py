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
import sys 

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
sys.path.append(PROJECT_ROOT)
from config import DATABASE_PATH, FRONTEND_DIR, WEB_CONFIG
print(f"前端文件托管路径：{FRONTEND_DIR}")
if not os.path.exists(FRONTEND_DIR):
    os.makedirs(FRONTEND_DIR, exist_ok=True)
    print(f"已自动创建前端目录：{FRONTEND_DIR}")


# -------------------------- 托管前端的路由（不用改） --------------------------
# 访问前端文件（如index.html、静态资源）
@app.route('/<path:filename>')
def serve_frontend(filename):
    file_path = os.path.join(FRONTEND_DIR, filename)
    if not os.path.exists(file_path):
        error_msg = f"文件未找到：{filename}（路径：{file_path}）"
        logger.error(error_msg)
        return error_msg, 404
    
    # 核心修复：给静态文件加明确MIME类型，解决“不支持该文件类型”
    response = make_response(send_from_directory(FRONTEND_DIR, filename))
    if filename.endswith('.html'):
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        logger.info(f"返回HTML文件：{filename}")
    elif filename.endswith('.js'):
        response.headers['Content-Type'] = 'application/javascript; charset=utf-8'  # JS正确类型
        logger.info(f"返回JS文件：{filename}")
    elif filename.endswith('.css'):
        response.headers['Content-Type'] = 'text/css; charset=utf-8'  # CSS正确类型
        logger.info(f"返回CSS文件：{filename}")
    elif filename.endswith(('.ico', '.png', '.jpg')):
        # 图片/图标类型，让浏览器正确识别
        if filename.endswith('.ico'):
            response.headers['Content-Type'] = 'image/x-icon'
        elif filename.endswith('.png'):
            response.headers['Content-Type'] = 'image/png'
        elif filename.endswith('.jpg'):
            response.headers['Content-Type'] = 'image/jpeg'
        logger.info(f"返回图片文件：{filename}")
    else:
        logger.info(f"返回静态文件：{filename}")
    return response


# 保留原有路由（必须！否则iframe加载子页面会404）
@app.route('/index.html')
def index_page():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/control.html')
def control_page():
    return send_from_directory(FRONTEND_DIR, 'control.html')

@app.route('/anomaly.html')
def anomaly_page():
    return send_from_directory(FRONTEND_DIR, 'anomaly.html')
# 访问根路径时返回index.html
@app.route('/')
def main_dashboard():
    return send_from_directory(FRONTEND_DIR, 'main_dashboard.html')

# -------------------------- 数据库工具函数 --------------------------
def get_db_connection():
    """获取数据库连接，自动适配字段名访问"""
    try:
        conn = sqlite3.connect(
            DATABASE_PATH,
            check_same_thread=False,  # 允许跨线程使用
            timeout=10.0  # 锁等待时间加长，避免并发锁冲突
        )
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
        # 核心流数据表（包含NetFlow v9核心字段）
        cursor.execute('''
    CREATE TABLE IF NOT EXISTS netflow (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        in_bytes INTEGER,
        out_bytes INTEGER DEFAULT 0,
        in_packets INTEGER,
        out_packets INTEGER DEFAULT 0,
        protocol INTEGER,
        src_port INTEGER,
        dst_port INTEGER,
        src_ip TEXT,
        dst_ip TEXT,
        timestamp INTEGER,
        first_switched INTEGER DEFAULT 0,  -- 新增
        last_switched INTEGER DEFAULT 0,   -- 新增
        tcp_flags INTEGER DEFAULT 0,
        is_processed INTEGER DEFAULT 0  -- 新增这一行，默认值0
    )
    ''')
        # 1. 补全netflow表的is_processed字段（已有逻辑保留）
        cursor.execute("PRAGMA table_info(netflow);")
        columns = [col[1] for col in cursor.fetchall()]
        if 'is_processed' not in columns:
            cursor.execute("ALTER TABLE netflow ADD COLUMN is_processed INTEGER DEFAULT 0;")
            logger.info(f"已为netflow表添加is_processed字段")

        cursor.execute('''
    CREATE TABLE IF NOT EXISTS anomaly_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id INTEGER NOT NULL,  -- 建表时直接添加，关联netflow的id
        src_ip TEXT,
        dst_ip TEXT,  -- 新增dst_ip字段
        in_bytes INTEGER,
        out_bytes INTEGER,  -- 新增出字节数
        in_packets INTEGER,
        out_packets INTEGER,  -- 新增出包数
        anomaly_score FLOAT,
        timestamp INTEGER,
        FOREIGN KEY (flow_id) REFERENCES netflow(id)  -- 外键关联（可选，增强数据完整性）
    )
    ''')

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
            LIMIT 500
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
    try:
        top_n = int(request.args.get('top_n', 5))
        hours = int(request.args.get('hours', 168))  # 默认7天
        ip_type = request.args.get('type', 'src')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 核心修复：只调用1次fetchone()，避免None时下标错误
        cursor.execute("SELECT timestamp FROM netflow LIMIT 1;")
        sample_row = cursor.fetchone()  # 只调用1次，存到变量
        sample_ts = sample_row['timestamp'] if sample_row else 0  # 先判断是否为None
        ts_divisor = 1000 if sample_ts > 1e12 else 1  # 毫秒级→除以1000转秒级
        logger.info(f"检测到timestamp单位：{'毫秒级' if ts_divisor==1000 else '秒级'}（除数：{ts_divisor}）")
        
        # SQL查询（适配timestamp单位）
        base_sql = f"""
            SELECT {ip_type}_ip AS ip,
                   DATE(timestamp / {ts_divisor}, 'unixepoch') AS date,
                   SUM(in_bytes) AS bytes
            FROM netflow
            WHERE 1=1
            
        """
        params = []
        if hours > 0:
            start_time_ts = int((datetime.now() - timedelta(hours=hours)).timestamp())
            base_sql += f" AND timestamp / {ts_divisor} >= ?"
            params.append(start_time_ts)
            logger.info(f"统计条件：最近{hours}小时（时间戳≥{start_time_ts}）")
        
        # 按日期升序，确保前端时间轴正确
        base_sql += f" GROUP BY ip, DATE(timestamp / {ts_divisor}, 'unixepoch') ORDER BY date ASC"
        cursor.execute(base_sql, params)
        results = cursor.fetchall()
        conn.close()
        logger.info(f"IP趋势接口查询到{len(results)}条原始数据")
        
        # 重构数据结构（前端图表友好格式）
        ip_map = {}
        for row in results:
            ip = row['ip']
            if ip not in ip_map:
                ip_map[ip] = {'ip': ip, 'history': []}
            ip_map[ip]['history'].append({
                'date': row['date'],
                'bytes': row['bytes'],
                'bytes_mb': round(row['bytes'] / 1024 / 1024, 2)  # 新增MB单位，方便前端显示
            })
        
        # 取TOP N IP（按总流量排序）
        real_data = sorted(
            ip_map.values(),
            key=lambda x: sum(h['bytes'] for h in x['history']),
            reverse=True
        )[:top_n]
        logger.info(f"IP趋势接口返回TOP {top_n} IP数据")
        return jsonify({
            'success': True,
            'data': real_data,
            'count': len(real_data),
            'ts_divisor': ts_divisor  # 告诉前端timestamp单位
        }), 200
    except Exception as e:
        logger.error(f"IP趋势接口错误：{str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

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
    
    conn = sqlite3.connect(DATABASE_PATH)
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
@app.route('/api/system/config', methods=['GET', 'POST'])
def system_config():
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT param_name, param_value 
                FROM model_config 
                WHERE param_name IN ('highRiskThreshold', 'midRiskThreshold', 'refreshInterval')
            """)
            results = cursor.fetchall()
            conn.close()

            config = {
                "highRiskThreshold": 0.8,
                "midRiskThreshold": 0.6,
                "refreshInterval": 30
            }
            for row in results:
                config[row['param_name']] = float(row['param_value'])
            logger.info(f"获取系统配置：{config}")
            return jsonify({'success': True, 'data': config}), 200
        except Exception as e:
            logger.error(f"获取系统配置错误：{str(e)}")
            return jsonify({'success': True, 'data': config}), 200  # 兜底返回默认值

    if request.method == 'POST':
        try:
            data = request.get_json()
            conn = get_db_connection()
            cursor = conn.cursor()

            # 更新配置到数据库
            for param_name, param_value in data.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO model_config (param_name, param_value, description)
                    VALUES (?, ?, ?)
                """, (param_name, param_value, f"系统配置：{param_name}"))
            
            conn.commit()
            conn.close()
            logger.info(f"保存系统配置：{data}")
            return jsonify({'success': True, 'msg': "配置保存成功"}), 200
        except Exception as e:
            logger.error(f"保存系统配置错误：{str(e)}")
            return jsonify({'success': False, 'error': str(e)}), 500




# ========== 系统状态接口 ==========
@app.route('/api/system/status', methods=['GET'])
def get_system_status():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 1. 统计今日异常数
        
        today_start = int(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        cursor.execute("""
            SELECT COUNT(*) as todayAnomalyCount 
            FROM anomaly_records 
            WHERE timestamp >= ?
        """, (today_start,))
        today_anomaly = cursor.fetchone()['todayAnomalyCount']
        # 2. 统计阻断IP数
        cursor.execute("SELECT COUNT(*) as blockedIpCount FROM blocked_ips")
        blocked_ips = cursor.fetchone()['blockedIpCount']
        # 3. 统计数据库大小
        cursor.execute("PRAGMA page_count")
        page_count = cursor.fetchone()[0]
        cursor.execute("PRAGMA page_size")
        page_size = cursor.fetchone()[0]
        db_size = page_count * page_size
        # 4. 计算系统运行时长（移到conn.close()之前）
        cursor.execute("SELECT param_value FROM model_config WHERE param_name = 'start_time'")
        start_time_row = cursor.fetchone()
        if start_time_row:
            start_time_ts = int(start_time_row['param_value'])
            run_seconds = int(time.time()) - start_time_ts
            run_time = f"{run_seconds//3600}小时{(run_seconds%3600)//60}分"
        else:
            run_time = "0小时0分"  # 兜底
        # 最后关闭conn
        conn.close()
        return jsonify({
            "success": True,
            "data": {
                "runTime": run_time,
                "blockedIpCount": blocked_ips,
                "todayAnomalyCount": today_anomaly,
                "dbSize": db_size
            }
        }), 200
    except Exception as e:
        app.logger.error(f"获取系统状态失败：{str(e)}")
        return jsonify({"success": False, "error": str(e), "data": {}}), 500



# ========== 阻断IP接口（拆分DELETE，解决405错误） ==========
# 原接口：只处理GET（查列表）、POST（新增阻断）
@app.route('/api/blocked-ips', methods=['GET', 'POST'])
def blocked_ips_list():
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ip, reason, block_time as blockTime FROM blocked_ips ORDER BY block_time DESC")
            results = cursor.fetchall()
            conn.close()
            data = [{k: row[k] for k in row.keys()} for row in results]
            logger.info(f"获取阻断IP列表：{len(data)}条")
            return jsonify({'success': True, 'data': data}), 200
        except Exception as e:
            logger.error(f"获取阻断IP错误：{str(e)}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            ip = data.get('ip')
            if not ip:
                return jsonify({'success': False, 'error': "缺少IP地址"}), 400
            
            conn = get_db_connection()
            conn.execute("BEGIN TRANSACTION")
            cursor = conn.cursor()
            # 写入数据库
            cursor.execute("""
                INSERT OR IGNORE INTO blocked_ips (ip, reason, block_time)
                VALUES (?, ?, strftime('%s', 'now'))
            """, (ip, data.get('reason', '手动阻断')))
            
            # 未开GNS3，跳过路由器操作，仅日志提示
            logger.warning(f"未开启GNS3，跳过路由器阻断操作（IP：{ip}）")
            
            conn.commit()
            conn.close()
            logger.info(f"手动阻断IP：{ip}（仅写入数据库）")
            return jsonify({'success': True, 'msg': f"IP {ip} 阻断成功（未同步路由器）"}), 200
        except Exception as e:
            if 'conn' in locals():
                conn.rollback()
                conn.close()
            logger.error(f"阻断IP错误：{str(e)}")
            return jsonify({'success': False, 'error': str(e)}), 500

# 新增接口：处理DELETE（解除阻断，带IP路径参数），解决405
@app.route('/api/blocked-ips/<string:ip>', methods=['DELETE'])
def unblock_ip(ip):
    try:
        if not ip:
            return jsonify({'success': False, 'error': "缺少IP地址"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        # 删除数据库记录
        cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        affected_rows = cursor.rowcount  # 检查是否有记录被删除
        conn.commit()
        conn.close()
        
        if affected_rows == 0:
            logger.warning(f"未找到IP {ip} 的阻断记录，无需解除")
            return jsonify({'success': True, 'msg': f"IP {ip} 无阻断记录"}), 200
        
        # 未开GNS3，跳过路由器操作
        logger.warning(f"未开启GNS3，跳过路由器解除操作（IP：{ip}）")
        logger.info(f"解除阻断IP：{ip}（已删除数据库记录）")
        return jsonify({'success': True, 'msg': f"IP {ip} 解除成功（未同步路由器）"}), 200
    except Exception as e:
        logger.error(f"解除阻断IP错误：{str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


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
    app.run(
        host=WEB_CONFIG["host"],
        port=WEB_CONFIG["port"],
        debug=WEB_CONFIG["debug"]
    )