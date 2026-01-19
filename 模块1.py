
# 新建 check_cic_columns.py，放在项目根目录
import pandas as pd

# 读取CIC合并文件的前10行，查看所有列名
cic_path = "data/CIC-DDoS2019_train.csv"
df = pd.read_csv(cic_path, nrows=10, low_memory=False)

# 打印所有列名
print("CIC数据集所有列名：")
for i, col in enumerate(df.columns, 1):
    print(f"{i:2d}. {col}")

# 特别查找包含“协议”含义的列（如Protocol、protocol、Transport Protocol）
protocol_cols = [col for col in df.columns if 'proto' in col.lower() or 'protocol' in col.lower()]
print(f"\n可能的协议列：{protocol_cols}")