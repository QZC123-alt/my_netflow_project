# 1. 顶部必须导入sys和os（确保不遗漏）
import sys
import os

# 2. 核心修复：用sys.argv[0]获取spec文件路径（替代__file__，适配Python 3.14）
# sys.argv[0]永远指向当前执行的spec文件，在打包时稳定可用
if len(sys.argv) > 0:
    spec_file_path = os.path.abspath(sys.argv[0])
    project_root = os.path.dirname(spec_file_path)  # 项目根目录=spec文件所在目录
else:
    # 兜底：若sys.argv异常，直接指定项目根目录（需手动替换为你的实际路径，如"D:\VS\project\Python\Python_Netflow"）
    project_root = "D:\\VS\\project\\Python\\Python_Netflow"

sys.path.append(project_root)  # 确保项目模块能被找到

# 3. 保留原有的Analysis、PYZ、EXE配置，仅修改datas路径（用project_root确保正确）
a = Analysis(
    ['main.py'],  # 入口脚本不变
    pathex=[project_root],
    binaries=[],
    # 4. 修复资源路径：用project_root拼接，避免相对路径错误
    datas=[
        (os.path.join(project_root, 'web', 'public'), 'web/public'),
        (os.path.join(project_root, 'models'), 'models'),
        (os.path.join(project_root, 'config.py'), '.'),
    ],
    # 5. 补充hiddenimports（基于你的requirements.txt，确保不遗漏核心模块）
    hiddenimports=[
        # 第三方依赖（从你的requirements.txt中提取核心库）
        'flask', 'flask_cors', 'werkzeug', 'jinja2',
        'pandas', 'numpy', 'scikit_learn', 'joblib',
        'paramiko', 'pyshark', 'matplotlib',
        # 你的项目自定义模块（确保所有文件夹下的py文件都包含）
        'anomaly_detection.merge_cic',
        'anomaly_detection.run_system',
        'api.anomaly_routes',
        'api.flask_server',
        'data_collection.collector_v9',
        'data_integration.flow_processor',
        'utils.log_utils'
    ],
    hookspath=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data)

# 6. EXE配置不变（保持控制台显示，方便查看日志）
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NetFlow入侵检测系统',
    debug=False,
    console=True,  # 必须保留，打包后能看到启动日志
    upx=True,
)