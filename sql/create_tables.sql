-- NetFlow数据表结构
CREATE TABLE IF NOT EXISTS netflow (
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
    tos INTEGER,
    -- 索引优化查询性能
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_protocol (protocol)
);