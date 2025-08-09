import hashlib
import random

def demo_password_checkup():
    """演示密码安全检查协议"""

    print("谷歌密码安全检查协议演示")
    print("=" * 40)

    # 客户端密码（一些会泄露，一些不会）
    client_passwords = [
        "mySecure123",     # 安全密码
        "password123",     # 常见泄露
        "uniquePass2024",  # 安全密码
        "123456",          # 高频泄露
        "qwerty",          # 常见泄露
        "strongPassword"   # 安全密码
    ]

    # 服务器泄露数据库（密码 -> 泄露次数）
    server_breach_db = {
        "password123": 15420,
        "123456": 235971,
        "qwerty": 39467,
        "admin": 1224,
        "letmein": 884,
        "welcome": 498,
        "monkey": 345,
        "dragon": 298,
        "football": 1234,
        "sunshine": 567
    }

    print(f"客户端密码数量：{len(client_passwords)}")
    print(f"服务器泄露数据库大小：{len(server_breach_db)}")

    # 计算实际交集（仅用于验证协议正确性）
    actual_compromised = set(client_passwords) & set(server_breach_db.keys())
    actual_total_breaches = sum(server_breach_db[pwd] for pwd in actual_compromised)

    print(f"\n实际情况（用于验证）：")
    print(f"   实际泄露密码：{list(actual_compromised)}")
    print(f"   实际总泄露次数：{actual_total_breaches}")

    print(f"\nDDH协议模拟执行：")
    print(f"第一轮：客户端用密钥k1掩码密码")
    print(f"第二轮：服务器用密钥k2处理并发送加密的泄露次数")
    print(f"第三轮：客户端计算交集并求和泄露次数")

    # 模拟协议计算
    print(f"\n协议执行中...")

    # 模拟客户端第一轮：哈希并掩码
    client_secret = random.randint(1000, 9999)
    client_masked = []
    for pwd in client_passwords:
        hash_val = int(hashlib.sha256(pwd.encode()).hexdigest()[:8], 16)
        masked = hash_val ^ client_secret  # 简化的掩码操作
        client_masked.append(masked)

    print(f"客户端发送 {len(client_masked)} 个掩码哈希值")

    # 模拟服务器第二轮：处理客户端数据，准备自己的数据
    server_secret = random.randint(1000, 9999)
    z_set = [val ^ server_secret for val in client_masked]

    server_data = []
    for pwd, count in server_breach_db.items():
        hash_val = int(hashlib.sha256(pwd.encode()).hexdigest()[:8], 16)
        server_masked = hash_val ^ server_secret
        server_data.append((server_masked, count))

    print(f"服务器发送Z集合和 {len(server_data)} 个数据条目")

    # 模拟客户端第三轮：计算交集
    intersection_count = 0
    total_breaches = 0

    for server_hash, breach_count in server_data:
        double_masked = server_hash ^ client_secret
        if double_masked in z_set:
            intersection_count += 1
            total_breaches += breach_count

    print(f"客户端计算出交集和总和")

    # 显示最终结果
    print(f"\n协议结果：")
    print(f"   发现泄露密码数：{intersection_count}")
    print(f"   总泄露次数：{total_breaches}")

    # 验证准确性
    accuracy = "正确" if (intersection_count == len(actual_compromised) and
                          total_breaches == actual_total_breaches) else "存在差异"
    print(f"   结果准确性：{accuracy}")

    print(f"\n隐私保护分析：")
    print(f"   服务器是否知道客户端具体密码：否")
    print(f"   客户端是否知道完整泄露数据库：否")
    print(f"   是否只透露聚合统计信息：是")
    print(f"   基于的密码学假设：DDH困难问题")

    print(f"\n安全建议：")
    if intersection_count > 0:
        avg_breaches = total_breaches / intersection_count
        print(f"   警告：{intersection_count} 个密码已在数据泄露中出现")
        print(f"   平均每个密码泄露 {avg_breaches:,.0f} 次")
        print(f"   建议：立即更换这些密码")
    else:
        print(f"   恭喜：所有密码都很安全，未在已知泄露中出现")



def show_protocol_details():
    """显示协议详细步骤"""

    print("\n" + "=" * 50)
    print("DDH协议详细步骤说明")
    print("=" * 50)

    print("\n准备阶段：")
    print("- 服务器生成Paillier密钥对，发送公钥给客户端")

    print("\n第一轮（客户端 -> 服务器）：")
    print("- 对每个密码p，计算 H(p)^k1（k1是客户端密钥）")
    print("- 将结果打乱顺序发送给服务器")

    print("\n第二轮（服务器 -> 客户端）：")
    print("- 收到客户端数据，计算 H(p)^(k1*k2)，得到Z集合")
    print("- 对泄露数据库中每个密码w，计算 H(w)^k2")
    print("- 用Paillier加密泄露次数，与H(w)^k2一起发送")

    print("\n第三轮（客户端 -> 服务器）：")
    print("- 对服务器发来的H(w)^k2，计算H(w)^(k1*k2)")
    print("- 检查是否在Z集合中，找出交集")
    print("- 同态求和对应的加密泄露次数")
    print("- 发送加密总和给服务器解密")

if __name__ == "__main__":
    demo_password_checkup()
    show_protocol_details()