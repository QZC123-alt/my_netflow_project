import socket
import struct
import random
import time

COLLECTOR_IP = "127.0.0.1"
COLLECTOR_PORT = 9995

def ip_to_int(ip):
    octets = list(map(int, ip.split('.')))
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]

def send_mock_netflow():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # -------------------------- 1. 发送模板包（保持正确） --------------------------
    sys_uptime = int(time.time() * 1000) % 0x100000000
    template_id = 256
    field_count = 7
    fields = [
        (4, 1),    # PROTOCOL
        (7, 2),    # L4_SRC_PORT
        (11, 2),   # L4_DST_PORT
        (8, 4),    # IPV4_SRC_ADDR
        (12, 4),   # IPV4_DST_ADDR
        (1, 4),    # IN_BYTES
        (10, 4)    # INPUT_INTERFACE_ID
    ]
    # 模板FlowSet长度：4(头) + 2(ID)+2(字段数) + 7*4(字段) = 36
    template_flow_set_len = 36
    template_packet = struct.pack(
        '!HHIIIIHHHHHHHHHHHHHHHHHH',
        9, 1,  # 版本、记录数
        sys_uptime, int(time.time()), 1, 1,  # 运行时间、时间戳、序列号、源ID
        0, template_flow_set_len,  # FlowSet ID、长度
        template_id, field_count,  # 模板ID、字段数
        # 字段定义
        fields[0][0], fields[0][1],
        fields[1][0], fields[1][1],
        fields[2][0], fields[2][1],
        fields[3][0], fields[3][1],
        fields[4][0], fields[4][1],
        fields[5][0], fields[5][1],
        fields[6][0], fields[6][1]
    )
    sock.sendto(template_packet, (COLLECTOR_IP, COLLECTOR_PORT))
    print(f"已发送模板包（长度：{len(template_packet)}字节）")
    time.sleep(2)


    # -------------------------- 2. 发送数据流包（核心修正：长度对齐+填充） --------------------------
    protocols = [6, 17, 1]
    protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
    for i in range(10):
        # 生成字段数据
        proto = random.choice(protocols)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 22])
        src_ip = ip_to_int(f"192.168.1.{random.randint(1,100)}")
        dst_ip = ip_to_int(f"8.8.8.{random.randint(1,4)}")
        bytes_num = random.randint(1000, 100000)
        input_if = random.randint(1, 10)

        # 关键修正1：FlowSet长度（4字节头 + 24字节流数据（含填充）=28）
        data_flow_set_len = 28
        # 关键修正2：添加3个填充字节（x），使流数据部分对齐到24字节（4字节整数倍）
        data_packet = struct.pack(
            '!HHIIIIHHBHHIIIIxxx',  # 末尾加xxx补3字节，确保流数据长度24
            # NetFlow头部
            9, 1,  # 版本、记录数
            int(time.time()*1000)%0x100000000, int(time.time()), i+2, 1,  # 运行时间、时间戳、序列号、源ID
            # FlowSet头
            template_id, data_flow_set_len,  # 模板ID、FlowSet长度（28）
            # 流数据（严格匹配模板）
            proto, src_port, dst_port, src_ip, dst_ip, bytes_num, input_if,
            # 填充字节（3个x，占3字节）
        )
        sock.sendto(data_packet, (COLLECTOR_IP, COLLECTOR_PORT))
        print(f"发送{protocol_names[proto]}流数据（长度：{len(data_packet)}字节）")
        time.sleep(0.5)

    sock.close()
    print("模拟数据发送完成！")

if __name__ == "__main__":
    send_mock_netflow()