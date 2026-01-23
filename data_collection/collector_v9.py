# collector_v9.py
import struct
import logging
import sqlite3
import os
import time
from threading import Lock

# ===================== 全局配置（可根据需求调整） =====================
# 数据库路径
DB_PATH =  'netflow.db'
# 批量写入阈值（生产环境可设为50，测试设为1）
BATCH_WRITE_THRESHOLD = 50
# 流缓存+锁（线程安全）
FLOW_CACHE = []
CACHE_LOCK = Lock()
# 日志配置
from utils.log_utils import get_module_logger
logger = get_module_logger("collector_v9")  # 日志文件：collector.log


# ===================== 数据库初始化 =====================
def createdb():
    """创建NetFlow数据库表（确保字段与解析的流数据匹配）"""
    conn = sqlite3.connect(DB_PATH)
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
    # 异常流量表（用于DDoS检测）
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
    conn.commit()
    conn.close()
    logging.info(f"数据库初始化完成 | 路径：{DB_PATH}")

# ===================== 模板字段解析类 =====================
class TemplateField:
    """模板字段模型（标准化字段类型+长度）"""
    def __init__(self, field_type: int, field_length: int):
        self.type = field_type
        self.length = field_length
        # 字段类型映射（NetFlow v9标准）
        self.type_name = {
            1: 'IN_BYTES', 8: 'IN_OCTETS', 12: 'IN_PKTS',
            4: 'PROTOCOL', 7: 'SRC_PORT', 11: 'DST_PORT',
            128: 'SRC_IP', 129: 'DST_IP'
        }.get(field_type, f'UNKNOWN_{field_type}')

    def __repr__(self):
        return f"TemplateField({self.type_name}, {self.length} bytes)"

# ===================== 模板记录类 =====================
class TemplateRecord:
    """模板记录模型（模板ID+字段列表）"""
    def __init__(self, template_id: int, fields: list[TemplateField]):
        self.template_id = template_id
        self.fields = fields
        # 预计算单条流的长度（避免重复计算）
        self.flow_length = sum([f.length for f in fields])

    def __repr__(self):
        return f"TemplateRecord(ID={self.template_id}, fields={self.fields})"

# ===================== 模板FlowSet解析 =====================
class TemplateFlowSet:
    """模板FlowSet解析（严格遵循NetFlow v9协议）"""
    @staticmethod
    def parse(flowset_data: bytes) -> list[TemplateRecord]:
        """
        解析模板FlowSet数据
        :param flowset_data: 模板FlowSet的字节数据（不含FlowSet头部）
        :return: 模板记录列表
        """
        templates = []
        offset = 0
        # 模板FlowSet数据长度需至少包含1个模板（模板ID+字段数=4字节）
        while offset + 4 <= len(flowset_data):
            # 解析模板ID（2字节）
            template_id = struct.unpack('!H', flowset_data[offset:offset+2])[0]
            offset += 2
            # 解析字段数（2字节）
            field_count = struct.unpack('!H', flowset_data[offset:offset+2])[0]
            offset += 2
            logging.info(f"解析模板 | ID：{template_id} | 字段数：{field_count}")

            # 解析字段列表
            fields = []
            for _ in range(field_count):
                if offset + 4 > len(flowset_data):
                    logging.error(f"模板{template_id}字段解析越界，终止解析")
                    break
                # 字段类型（2字节）+ 字段长度（2字节）
                f_type = struct.unpack('!H', flowset_data[offset:offset+2])[0]
                f_len = struct.unpack('!H', flowset_data[offset+2:offset+4])[0]
                fields.append(TemplateField(f_type, f_len))
                offset += 4

            # 生成模板记录并加入列表
            if fields:
                template = TemplateRecord(template_id, fields)
                templates.append(template)
                logging.info(f"模板{template_id}解析完成 | 字段：{fields}")
            else:
                logging.warning(f"模板{template_id}无有效字段，跳过")

        return templates

# ===================== 数据FlowSet解析 =====================
# collector_v9.py 中 DataFlowSet.parse() 方法
class DataFlowSet:
    """数据FlowSet解析（基于模板）- 适配原有netflow表结构"""
    @staticmethod
    def parse(flowset_data: bytes, template: TemplateRecord) -> list[dict]:
        """
        解析数据FlowSet为流字典列表（适配原有表字段：in_bytes/in_pkts等）
        :param flowset_data: 数据FlowSet的字节数据（不含FlowSet头部）
        :param template: 匹配的模板记录
        :return: 流字典列表（字段名100%适配原有表）
        """
        flows = []
        flow_length = template.flow_length
        if flow_length == 0 or len(flowset_data) % flow_length != 0:
            logging.error(f"流数据长度({len(flowset_data)})与模板{template.template_id}单条流长度({flow_length})不匹配")
            return flows

        # 解析所有流
        for i in range(0, len(flowset_data), flow_length):
            flow_data = flowset_data[i:i+flow_length]
            offset = 0
            flow = {}
            for field in template.fields:
                if offset + field.length > len(flow_data):
                    logging.error(f"流{i//flow_length}字段{field.type_name}解析越界，跳过该流")
                    break
                
                # ========== 核心修改1：字段名映射（适配原有表） ==========
                if field.type == 8:  # IN_OCTETS → 映射为原有表的in_bytes
                    flow['in_bytes'] = struct.unpack('!I', flow_data[offset:offset+4])[0]
                elif field.type == 10:  # OUT_OCTETS（目的字节数，对应NetFlow字段类型10）
                    flow['out_bytes'] = struct.unpack('!I', flow_data[offset:offset+4])[0]
                elif field.type == 12:  # IN_PKTS → 保持和原有表一致
                    flow['in_packets'] = struct.unpack('!I', flow_data[offset:offset+4])[0]
                elif field.type == 13:  # OUT_PKTS（目的包数，对应NetFlow字段类型13）
                    flow['out_packets'] = struct.unpack('!I', flow_data[offset:offset+4])[0]
                elif field.type == 4:  # PROTOCOL → 保持一致
                    flow['protocol'] = struct.unpack('!H', flow_data[offset:offset+2])[0]
                elif field.type == 7:  # SRC_PORT → 保持一致
                    flow['src_port'] = struct.unpack('!H', flow_data[offset:offset+2])[0]
                elif field.type == 11:  # DST_PORT → 保持一致
                    flow['dst_port'] = struct.unpack('!H', flow_data[offset:offset+2])[0]
                elif field.type == 128:  # SRC_IP → 解析为点分十进制（适配模型）
                    src_ip_bytes = flow_data[offset:offset+4]
                    flow['src_ip'] = '.'.join(map(str, struct.unpack('!4B', src_ip_bytes)))
                elif field.type == 129:  # DST_IP → 解析为点分十进制（适配模型）
                    dst_ip_bytes = flow_data[offset:offset+4]
                    flow['dst_ip'] = '.'.join(map(str, struct.unpack('!4B', dst_ip_bytes)))
                elif field.type == 21:  # LAST_SWITCHED（对应NetFlow字段类型21）
                    flow['last_switched'] = struct.unpack('!I', flow_data[offset:offset+4])[0]
                elif field.type == 22:  # FIRST_SWITCHED（对应NetFlow字段类型22）
                    flow['first_switched'] = struct.unpack('!I', flow_data[offset:offset+4])[0]
                elif field.type == 23:  # TCP_FLAGS（NetFlow字段类型23
                    flow['tcp_flags'] = struct.unpack('!B', flow_data[offset:offset+1])[0]
                    
                    
                else:  # 其他字段暂不处理
                    pass
                
                offset += field.length

            if flow:
                # 补充时间戳（适配原有表）
                flow['timestamp'] = int(time.time())
                flow['is_processed'] = 0
                flows.append(flow)
                logging.debug(f"解析流{i//flow_length} | 适配后数据：{flow}")

        logging.info(f"模板{template.template_id}解析出{len(flows)}条流（字段名已适配原有表）")
        return flows

# ===================== 导出报文解析（核心类） =====================
class ExportPacket:
    """NetFlow v9导出报文解析器"""
    def __init__(self, data: bytes, templates: dict[int, TemplateRecord]):
        """
        初始化并解析NetFlow v9报文
        :param data: UDP接收的字节数据
        :param templates: 全局模板缓存（{模板ID: TemplateRecord}）
        """
        self.raw_data = data
        self.templates = templates  # 传入的全局模板缓存
        self.flows = []  # 解析出的流列表
        self.header = self._parse_header()  # 解析报文头部

        # 解析FlowSet（核心逻辑）
        self._parse_flowsets()

    def _parse_header(self) -> dict:
        """解析NetFlow v9报文头部（前22字节）"""
        if len(self.raw_data) < 22:
            raise ValueError(f"报文长度({len(self.raw_data)})不足22字节，无法解析头部")
        
        header_data = self.raw_data[:22]
        # 头部字段：版本(2)+FlowSet数(2)+系统启动时间(4)+UNIX秒(4)+UNIX纳秒(4)+序列号(4)+源ID(2)
        # 修复3：格式字符串对应22字节（HHIIIIH → 2+2+4+4+4+4+2=22）
        header_fields = struct.unpack('!HHIIIIH', header_data)
        header = {
            'version': header_fields[0],
            'flowset_count': header_fields[1],
            'sys_uptime': header_fields[2],
            'unix_secs': header_fields[3],
            'unix_nsecs': header_fields[4],
            'sequence': header_fields[5],
            'source_id': header_fields[6]
        }

        if header['version'] != 9:
            raise ValueError(f"非NetFlow v9报文（版本：{header['version']}）")
        logging.info(f"解析报文头部 | 版本：9 | FlowSet数：{header['flowset_count']} | 源ID：{header['source_id']}")
        return header

    def _parse_flowsets(self):
        """解析报文内的所有FlowSet"""
        offset = 22  # 跳过头部22字节
        while offset + 4 <= len(self.raw_data):  # FlowSet头部至少4字节（类型+长度）
            # 解析FlowSet头部：类型(2)+长度(2)
            flowset_type = struct.unpack('!H', self.raw_data[offset:offset+2])[0]
            flowset_length = struct.unpack('!H', self.raw_data[offset+2:offset+4])[0]
            offset += 4

            # 校验FlowSet长度
            if flowset_length < 4 or offset + flowset_length - 4 > len(self.raw_data):
                logging.error(f"FlowSet{flowset_type}长度({flowset_length})非法，跳过")
                offset = len(self.raw_data)  # 终止解析
                continue

            # 提取FlowSet数据（不含头部4字节）
            flowset_data = self.raw_data[offset:offset + flowset_length - 4]
            offset += flowset_length - 4

            # 1. 模板FlowSet（Type=0）
            if flowset_type == 0:
                new_templates = TemplateFlowSet.parse(flowset_data)
                # 更新全局模板缓存
                for template in new_templates:
                    self.templates[template.template_id] = template
                logging.info(f"模板FlowSet解析完成 | 新增模板数：{len(new_templates)} | 全局模板数：{len(self.templates)}")
            
            # 2. 数据FlowSet（Type=模板ID）
            elif flowset_type in self.templates:
                template = self.templates[flowset_type]
                new_flows = DataFlowSet.parse(flowset_data, template)
                self.flows.extend(new_flows)
                logging.info(f"数据FlowSet{flowset_type}解析完成 | 新增流数：{len(new_flows)} | 总流数：{len(self.flows)}")
            
            # 3. 未知FlowSet
            else:
                logging.warning(f"未知FlowSet类型：{flowset_type} | 无匹配模板，跳过")

# ===================== 批量写入数据库（线程安全） =====================
def batch_write_netflow(flow: dict):
    """
    线程安全的流数据批量写入
    :param flow: 单条流字典
    """
    with CACHE_LOCK:
        FLOW_CACHE.append(flow)
        # 达到阈值时写入数据库
        if len(FLOW_CACHE) >= BATCH_WRITE_THRESHOLD:
            _write_to_db(FLOW_CACHE.copy())
            # 清空缓存（仅保留未写入的部分，防止丢失）
            del FLOW_CACHE[:len(FLOW_CACHE)]

def _write_to_db(flows: list[dict]):
    """实际写入数据库的内部函数"""
    if not flows:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # 批量插入（提升性能）
        placeholders = ', '.join([':' + k for k in flows[0].keys()])
        sql = f"INSERT INTO netflow ({', '.join(flows[0].keys())}) VALUES ({placeholders})"
        cursor.executemany(sql, flows)
        conn.commit()
        logging.info(f"批量写入数据库 | 条数：{len(flows)} | 影响行数：{cursor.rowcount}")
    except sqlite3.Error as e:
        logging.error(f"数据库写入失败：{str(e)} | 待写入数据：{flows[:1]}")
    finally:
        conn.close()

# ===================== 兜底写入（程序退出时调用） =====================
def flush_cache():
    """程序退出时，将缓存中剩余的流写入数据库"""
    with CACHE_LOCK:
        if FLOW_CACHE:
            _write_to_db(FLOW_CACHE)
            logging.info(f"兜底写入缓存流 | 条数：{len(FLOW_CACHE)}")
            FLOW_CACHE.clear()

# 程序退出时自动兜底写入
import atexit
atexit.register(flush_cache)