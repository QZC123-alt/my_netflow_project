# Python_Netflow

#### 项目介绍
（亁颐堂现任明教教主技术进化论40期,Python Netflow配套代码） :smiley: 
现在被我征用了

#### 软件架构
Python

#### 运行
直接运行main.py即可

# 基于NetFlow的轻量化网络入侵检测与响应系统
## 项目定位
轻量型网络安全系统，核心是NetFlow流量驱动的入侵检测+安全联动闭环，适配中小型/实验网络环境，聚焦DDoS攻击、端口扫描等常见威胁，实现“采集→检测→告警→阻断→审计”全流程自动化处理。

## 核心目标
精准识别异常流量（DDoS、端口扫描等），通过轻量化技术栈构建完整安全流程，兼顾实用性与演示性，支持快速部署与增量迭代。

## 核心技术栈
### 开发环境
- 操作系统：Windows 11
- 模拟环境：GNS3 2.2.55（含Cisco IOS 15.4(3)M2）
- 开发语言：Python 3.14

### 核心库
- 数据处理：pandas 2.3.3、numpy 2.3.4
- 算法与特征工程：scikit-learn 1.8.0（随机森林+特征筛选）、joblib 1.3.2
- 可视化：matplotlib 3.7.0+、plotly 5.16.0+、Grafana 10.0+
- 交互与告警：tkinter、smtplib
- 数据存储：SQLite
- 流量处理：scapy 2.5.0、pyshark 0.5.3、netaddr 0.8.0

### 工具
- 流量导出/验证：+Wireshark 4.0+
- 安全联动：Snort 3.1.60+（暂时未实装）

### 开源复用
- 项目：Python_Netflow（Gitee地址：https://gitee.com/qytang/Python_Netflow.git）
- 复用范围：NetFlow v9协议解析、流量采集功能

## 系统核心模块
1. 数据采集层：NetFlow v9协议采集 → 开源项目解析 → 同步至处理模块
2. 数据处理层：pandas清洗 → scikit-learn特征工程
3. 安全分析层：随机森林模型训练 → 多线程批量推理 → 增量训练
4. 可视化层：静态图表+交互式仪表盘+实时异常列表
5. 安全联动层：弹窗/邮件告警 → ip阻断 → 误报标记
6. 日志审计层：双表存储 → 多维度查询


## 技术路线
数据采集 → 数据处理 → 分析检测 → 展示应用（可视化+权限+安全联动+日志）

## 依赖清单（requirements.txt）
```txt
appdirs         1.4.4
asgiref         3.11.0
contourpy       1.3.3
cycler          0.12.1
Django          6.0.1
fonttools       4.61.1
joblib          1.3.2
kiwisolver      1.4.9
lxml            6.0.2
matplotlib      3.7.0
netaddr         0.8.0
numpy           2.3.4
packaging       25.0
pandas          2.3.3
pillow          12.1.0
pip             25.3
plotly          5.16.0
py              1.11.0
PyMySQL         1.1.0
pyparsing       3.3.1
pyshark         0.5.3
python-dateutil 2.9.0.post0
pytz            2025.2
scapy           2.5.0
scikit-learn    1.8.0
scipy           1.16.3
six             1.17.0
sqlparse        0.5.5
tenacity        9.1.2
threadpoolctl   3.6.0
tzdata          2025.2