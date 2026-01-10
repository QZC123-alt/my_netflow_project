# main.py
# 智能网络流量异常检测系统（正式版：独立训练集与测试集）

import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# 1. 加载数据并添加列名
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate','label'
]

print("📂 正在加载数据集...")
train_data = pd.read_csv('data/KDDTrain+.csv', names=columns)
test_data  = pd.read_csv('data/KDDTest+.csv',  names=columns)

print(f"训练集样本数: {train_data.shape[0]}, 测试集样本数: {test_data.shape[0]}")

# 2. 标签编码与标准化
print("🔧 正在执行特征编码与标准化...")

encoder = LabelEncoder()
for col in train_data.columns:
    if train_data[col].dtype == 'object':
        # 训练集 + 测试集合并后统一编码，确保类别一致
        combined = pd.concat([train_data[col], test_data[col]], axis=0)
        encoder.fit(combined)
        train_data[col] = encoder.transform(train_data[col])
        test_data[col]  = encoder.transform(test_data[col])

scaler = StandardScaler()
X_train = scaler.fit_transform(train_data.drop('label', axis=1))
y_train = train_data['label']
X_test  = scaler.transform(test_data.drop('label', axis=1))
y_test  = test_data['label']

# 再次对标签统一编码
y_encoder = LabelEncoder()
combined_labels = pd.concat([y_train, y_test], axis=0)
y_encoder.fit(combined_labels)
y_train = y_encoder.transform(y_train)
y_test  = y_encoder.transform(y_test)

# 3. 模型训练
print("🚀 正在训练随机森林模型...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("✅ 模型训练完成")

# 4. 模型测试与评估
print("🧩 正在测试模型性能...")
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
rec = recall_score(y_test, y_pred, average='macro')
f1  = f1_score(y_test, y_pred, average='macro')

print(f"Accuracy: {acc:.4f}")
print(f"Recall: {rec:.4f}")
print(f"F1 Score: {f1:.4f}")

# 5. 混淆矩阵可视化
print("📊 正在生成混淆矩阵...")
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8,6))
sns.heatmap(cm, cmap='Blues', annot=False)
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')

plt.savefig('confusion_matrix_official.png', dpi=300, bbox_inches='tight')
plt.show()

print("🎯 实验结束，结果图已保存为 confusion_matrix.png")