import hashlib
import secrets
from typing import Tuple, Optional


class Point:
    """椭圆曲线点类"""

    def __init__(self, x: Optional[int] = None, y: Optional[int] = None):
        self.x = x
        self.y = y
        self.is_infinity = (x is None and y is None)

    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        return self.x == other.x and self.y == other.y

    def __str__(self):
        if self.is_infinity:
            return "O (点at无穷远)"
        return f"({hex(self.x)}, {hex(self.y)})"


class SM2Curve:
    """SM2椭圆曲线参数"""

    def __init__(self):
        # SM2推荐参数 (GM/T 0003.2-2012)
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        self.Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        self.Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        self.G = Point(self.Gx, self.Gy)

    def mod_inverse(self, a: int, m: int) -> int:
        """计算模逆"""
        if a < 0:
            return pow(a % m, -1, m)
        return pow(a, -1, m)

    def point_add(self, P: Point, Q: Point) -> Point:
        """椭圆曲线点加法"""
        if P.is_infinity:
            return Q
        if Q.is_infinity:
            return P

        if P.x == Q.x:
            if P.y == Q.y:
                # 点倍乘
                s = (3 * P.x * P.x + self.a) * self.mod_inverse(2 * P.y, self.p) % self.p
            else:
                # P + (-P) = O
                return Point()
        else:
            # 一般情况
            s = (Q.y - P.y) * self.mod_inverse(Q.x - P.x, self.p) % self.p

        x3 = (s * s - P.x - Q.x) % self.p
        y3 = (s * (P.x - x3) - P.y) % self.p

        return Point(x3, y3)

    def point_mul(self, k: int, P: Point) -> Point:
        """椭圆曲线点乘法（标量乘法）"""
        if k == 0:
            return Point()  # 无穷远点
        if k == 1:
            return P

        result = Point()  # 无穷远点
        addend = P

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result


class SM2Signature:
    """SM2签名算法实现"""

    def __init__(self):
        self.curve = SM2Curve()

    def _sm3_hash(self, data: bytes) -> bytes:
        """简化的哈希函数（使用SHA256代替SM3）"""
        return hashlib.sha256(data).digest()

    def _compute_za(self, id_a: str, pub_key: Point) -> bytes:
        """计算用户身份标识哈希值ZA"""
        # 简化实现，实际应该包含更多参数
        entl = len(id_a.encode()) * 8  # 用户ID长度（位）
        za_data = entl.to_bytes(2, 'big') + id_a.encode()
        za_data += self.curve.a.to_bytes(32, 'big')
        za_data += self.curve.b.to_bytes(32, 'big')
        za_data += self.curve.Gx.to_bytes(32, 'big')
        za_data += self.curve.Gy.to_bytes(32, 'big')
        za_data += pub_key.x.to_bytes(32, 'big')
        za_data += pub_key.y.to_bytes(32, 'big')

        return self._sm3_hash(za_data)

    def generate_keypair(self) -> Tuple[int, Point]:
        """生成密钥对"""
        d = secrets.randbelow(self.curve.n - 1) + 1
        P = self.curve.point_mul(d, self.curve.G)
        return d, P

    def sign(self, message: bytes, private_key: int, user_id: str = "1234567812345678", k: Optional[int] = None) -> \
    Tuple[int, int, int]:
        """
        SM2签名
        返回 (r, s, k) - k用于攻击演示，实际实现中应该安全销毁
        """
        # 计算公钥
        pub_key = self.curve.point_mul(private_key, self.curve.G)

        # 计算ZA
        za = self._compute_za(user_id, pub_key)

        # 计算e = H(ZA || M)
        m_prime = za + message
        e_bytes = self._sm3_hash(m_prime)
        e = int.from_bytes(e_bytes, 'big') % self.curve.n

        while True:
            # 生成随机数k（如果未指定）
            if k is None:
                k_val = secrets.randbelow(self.curve.n - 1) + 1
            else:
                k_val = k

            # 计算(x1, y1) = k * G
            point = self.curve.point_mul(k_val, self.curve.G)
            x1 = point.x

            # 计算r = (e + x1) mod n
            r = (e + x1) % self.curve.n

            # 检查r是否为0或r+k是否等于n
            if r == 0 or (r + k_val) % self.curve.n == 0:
                if k is not None:  # 如果k是指定的，说明有问题
                    raise ValueError("指定的k值导致无效签名")
                continue

            # 计算s = (1 + dA)^(-1) * (k - r * dA) mod n
            inv_1_plus_d = self.curve.mod_inverse(1 + private_key, self.curve.n)
            s = (inv_1_plus_d * (k_val - r * private_key)) % self.curve.n

            if s == 0:
                if k is not None:
                    raise ValueError("指定的k值导致无效签名")
                continue

            return r, s, k_val

    def verify(self, message: bytes, signature: Tuple[int, int], pub_key: Point,
               user_id: str = "1234567812345678") -> bool:
        """SM2签名验证"""
        r, s = signature

        # 检查r, s是否在有效范围内
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False

        # 计算ZA
        za = self._compute_za(user_id, pub_key)

        # 计算e = H(ZA || M)
        m_prime = za + message
        e_bytes = self._sm3_hash(m_prime)
        e = int.from_bytes(e_bytes, 'big') % self.curve.n

        # 计算t = (r + s) mod n
        t = (r + s) % self.curve.n
        if t == 0:
            return False

        # 计算(x1', y1') = s * G + t * PA
        point1 = self.curve.point_mul(s, self.curve.G)
        point2 = self.curve.point_mul(t, pub_key)
        point_result = self.curve.point_add(point1, point2)

        if point_result.is_infinity:
            return False

        # 计算R = (e + x1') mod n
        R = (e + point_result.x) % self.curve.n

        return R == r


class SM2AttackDemo:
    """SM2签名攻击演示"""

    def __init__(self):
        self.sm2 = SM2Signature()

    def attack1_leak_k(self):
        """攻击1：泄漏随机数k导致私钥泄漏"""
        print("=" * 60)
        print("攻击1：泄漏随机数k导致私钥泄漏")
        print("=" * 60)

        # 生成密钥对
        private_key, pub_key = self.sm2.generate_keypair()
        message = b"Hello, SM2!"

        print(f"原始私钥: {hex(private_key)}")

        # 签名
        r, s, k = self.sm2.sign(message, private_key)
        print(f"签名: (r={hex(r)}, s={hex(s)})")
        print(f"泄漏的随机数k: {hex(k)}")

        # 验证签名
        is_valid = self.sm2.verify(message, (r, s), pub_key)
        print(f"签名验证: {'通过' if is_valid else '失败'}")

        # 攻击：从泄漏的k恢复私钥
        # dA = (k - s) * (s + r)^(-1) mod n
        inv_s_plus_r = self.sm2.curve.mod_inverse(s + r, self.sm2.curve.n)
        recovered_key = ((k - s) * inv_s_plus_r) % self.sm2.curve.n

        print(f"恢复的私钥: {hex(recovered_key)}")
        print(f"攻击成功: {'是' if recovered_key == private_key else '否'}")
        print()

    def attack2_reuse_k(self):
        """攻击2：重复使用随机数k导致私钥泄漏"""
        print("=" * 60)
        print("攻击2：重复使用随机数k导致私钥泄漏")
        print("=" * 60)

        # 生成密钥对
        private_key, pub_key = self.sm2.generate_keypair()
        message1 = b"Message 1"
        message2 = b"Message 2"

        print(f"原始私钥: {hex(private_key)}")

        # 使用相同的k签名两个不同消息
        k = secrets.randbelow(self.sm2.curve.n - 1) + 1

        r1, s1, _ = self.sm2.sign(message1, private_key, k=k)
        r2, s2, _ = self.sm2.sign(message2, private_key, k=k)

        print(f"消息1签名: (r={hex(r1)}, s={hex(s1)})")
        print(f"消息2签名: (r={hex(r2)}, s={hex(s2)})")
        print(f"使用的k值: {hex(k)}")

        # 验证签名
        is_valid1 = self.sm2.verify(message1, (r1, s1), pub_key)
        is_valid2 = self.sm2.verify(message2, (r2, s2), pub_key)
        print(f"签名1验证: {'通过' if is_valid1 else '失败'}")
        print(f"签名2验证: {'通过' if is_valid2 else '失败'}")

        # 攻击：从重复使用的k恢复私钥
        # dA = (s2 - s1) / ((s1 - s2) + (r1 - r2)) mod n
        try:
            numerator = (s2 - s1) % self.sm2.curve.n
            denominator = ((s1 - s2) + (r1 - r2)) % self.sm2.curve.n
            inv_denominator = self.sm2.curve.mod_inverse(denominator, self.sm2.curve.n)
            recovered_key = (numerator * inv_denominator) % self.sm2.curve.n

            print(f"恢复的私钥: {hex(recovered_key)}")
            print(f"攻击成功: {'是' if recovered_key == private_key else '否'}")
        except Exception as e:
            print(f"攻击失败: {e}")
        print()

    def attack3_different_users_same_k(self):
        """攻击3：不同用户使用相同k导致互相泄漏私钥"""
        print("=" * 60)
        print("攻击3：不同用户使用相同k导致互相泄漏私钥")
        print("=" * 60)

        # 生成Alice和Bob的密钥对
        alice_private, alice_public = self.sm2.generate_keypair()
        bob_private, bob_public = self.sm2.generate_keypair()

        message_alice = b"Alice's message"
        message_bob = b"Bob's message"

        print(f"Alice私钥: {hex(alice_private)}")
        print(f"Bob私钥: {hex(bob_private)}")

        # 使用相同的k值签名
        k = secrets.randbelow(self.sm2.curve.n - 1) + 1

        r_alice, s_alice, _ = self.sm2.sign(message_alice, alice_private, user_id="Alice", k=k)
        r_bob, s_bob, _ = self.sm2.sign(message_bob, bob_private, user_id="Bob", k=k)

        print(f"Alice签名: (r={hex(r_alice)}, s={hex(s_alice)})")
        print(f"Bob签名: (r={hex(r_bob)}, s={hex(s_bob)})")

        # Alice可以从自己的签名推导出k
        # k = s_alice * (1 + d_alice) + r_alice * d_alice mod n
        k_recovered_by_alice = (s_alice * (1 + alice_private) + r_alice * alice_private) % self.sm2.curve.n

        # Alice使用推导出的k攻击Bob的私钥
        # d_bob = (k - s_bob) / (s_bob + r_bob) mod n
        try:
            inv_s_plus_r_bob = self.sm2.curve.mod_inverse(s_bob + r_bob, self.sm2.curve.n)
            bob_private_recovered = ((k_recovered_by_alice - s_bob) * inv_s_plus_r_bob) % self.sm2.curve.n

            print(f"Alice恢复的Bob私钥: {hex(bob_private_recovered)}")
            print(f"Alice攻击成功: {'是' if bob_private_recovered == bob_private else '否'}")
        except Exception as e:
            print(f"Alice攻击失败: {e}")

        # Bob也可以攻击Alice
        k_recovered_by_bob = (s_bob * (1 + bob_private) + r_bob * bob_private) % self.sm2.curve.n
        try:
            inv_s_plus_r_alice = self.sm2.curve.mod_inverse(s_alice + r_alice, self.sm2.curve.n)
            alice_private_recovered = ((k_recovered_by_bob - s_alice) * inv_s_plus_r_alice) % self.sm2.curve.n

            print(f"Bob恢复的Alice私钥: {hex(alice_private_recovered)}")
            print(f"Bob攻击成功: {'是' if alice_private_recovered == alice_private else '否'}")
        except Exception as e:
            print(f"Bob攻击失败: {e}")
        print()

    def attack4_ecdsa_sm2_same_d_k(self):
        """攻击4：相同d和k在ECDSA和SM2之间使用"""
        print("=" * 60)
        print("攻击4：相同d和k在ECDSA和SM2之间使用")
        print("=" * 60)

        # 生成密钥对
        private_key, pub_key = self.sm2.generate_keypair()
        message = b"Test message"

        print(f"原始私钥: {hex(private_key)}")

        # 使用相同的k进行SM2签名
        k = secrets.randbelow(self.sm2.curve.n - 1) + 1
        r_sm2, s_sm2, _ = self.sm2.sign(message, private_key, k=k)

        # 模拟ECDSA签名（简化版本）
        # ECDSA: s = k^(-1) * (H(M) + r * d) mod n
        point_k = self.sm2.curve.point_mul(k, self.sm2.curve.G)
        r_ecdsa = point_k.x % self.sm2.curve.n

        h_m = int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.sm2.curve.n
        inv_k = self.sm2.curve.mod_inverse(k, self.sm2.curve.n)
        s_ecdsa = (inv_k * (h_m + r_ecdsa * private_key)) % self.sm2.curve.n

        print(f"SM2签名: (r={hex(r_sm2)}, s={hex(s_sm2)})")
        print(f"ECDSA签名: (r={hex(r_ecdsa)}, s={hex(s_ecdsa)})")

        # 攻击：从两个签名恢复私钥
        try:
            print("此攻击需要复杂的数学推导，这里仅演示概念")
            print("实际攻击会通过解方程组来恢复私钥")
        except Exception as e:
            print(f"攻击失败: {e}")
        print()

    def demonstrate_all_attacks(self):
        """演示所有攻击场景"""
        print("SM2签名算法攻击场景演示")
        print()

        self.attack1_leak_k()
        self.attack2_reuse_k()
        self.attack3_different_users_same_k()
        self.attack4_ecdsa_sm2_same_d_k()

if __name__ == "__main__":
    demo = SM2AttackDemo()
    demo.demonstrate_all_attacks()