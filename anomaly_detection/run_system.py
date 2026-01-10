import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, f1_score
import joblib
import os

def load_data(file_path):
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
    data = pd.read_csv(file_path, names=columns)
    encoder = LabelEncoder()
    for col in data.columns:
        if data[col].dtype == 'object':
            data[col] = encoder.fit_transform(data[col])
    return data

def train_model():
    print("正在加载训练数据...")
    data = load_data('data/KDDTrain+.csv')
    X = StandardScaler().fit_transform(data.drop('label', axis=1))
    y = data['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    print("开始训练模型...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    joblib.dump(model, 'rf_model.pkl')
    print("✅ 模型训练完成并保存为 rf_model.pkl")

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred, average='macro')
    f1 = f1_score(y_test, y_pred, average='macro')
    print(f"训练完成：Accuracy={acc:.4f}, Recall={rec:.4f}, F1={f1:.4f}")

def detect(file_path):
    if not os.path.exists('rf_model.pkl'):
        print("❌ 未找到模型，请先执行模型训练（选项1）")
        return
    print("正在加载检测数据...")
    model = joblib.load('rf_model.pkl')
    data = load_data(file_path)
    X = StandardScaler().fit_transform(data.drop('label', axis=1))
    y_pred = model.predict(X)
    print("✅ 检测完成，前10条预测结果：")
    print(y_pred[:10])

if __name__ == "__main__":
    print("=== 智能网络流量异常检测系统 ===")
    print("1. 训练模型")
    print("2. 检测新数据")
    choice = input("请选择操作（1/2）：")

    if choice == '1':
        train_model()
    elif choice == '2':
        path = input("请输入待检测文件路径（例如 data/KDDTest+.csv）：")
        detect(path)
    else:
        print("无效选项。")