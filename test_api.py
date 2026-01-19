import requests

# 服务基础地址
BASE_URL = "http://localhost:8000"


def test_health_check():
    """测试健康检查接口"""
    print("=== 1. 测试健康检查 ===")
    url = f"{BASE_URL}/api/anomaly/health"
    response = requests.get(url)
    print(f"状态码：{response.status_code}")
    print(f"响应：{response.json()}\n")


def test_model_status():
    print("=== 2. 测试模型状态 ===")
    url = f"{BASE_URL}/api/anomaly/status"
    try:
        response = requests.get(url)
        print(f"状态码：{response.status_code}")
        # 先判断响应是否是JSON格式
        if response.headers.get('Content-Type') == 'application/json':
            print(f"响应：{response.json()}\n")
        else:
            print(f"响应（非JSON）：{response.text[:200]}...\n")  # 打印部分内容排查
    except Exception as e:
        print(f"请求失败：{str(e)}\n")


def test_train_model():
    """测试训练接口"""
    print("=== 3. 测试训练模型 ===")
    url = f"{BASE_URL}/api/anomaly/train"
    response = requests.post(url)
    print(f"状态码：{response.status_code}")
    print(f"响应：{response.json()}\n")


def test_detect():
    print("=== 测试异常检测 ===")
    url = f"{BASE_URL}/api/anomaly/detect"
    # 示例特征（必须和FEATURE_COLS顺序完全一致）
    sample_features = [
        0, 'tcp', 'http', 'SF', 181, 5450, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0.0,
        0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 9,
        9, 1.0, 0.0, 0.11,
        0.0, 0.0, 0.0, 0.0, 0.0
    ]
    data = {"features": sample_features}  # 必须是"features"字段
    print("发送的请求数据:", data)  # 添加这行打印
    response = requests.post(url, json=data)
    print(f"状态码: {response.status_code}")
    print(f"响应: {response.json()}")

if __name__ == "__main__":
    test_health_check()
    test_model_status()
    test_train_model()
    # 训练完成后再测试检测（需等待训练结束）
    input("请等待训练完成后按回车键继续测试检测...")
    test_detect()