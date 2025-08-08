import hashlib
import secrets
import struct
from typing import Tuple, Optional


class Point:
    """椭圆曲线上的点"""

    def __init__(self, x: Optional[int], y: Optional[int]):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.x is None:
            return "Point(infinity)"
        return f"Point({self.x:x}, {self.y:x})"


class ECDSA:
    """ECDSA椭圆曲线数字签名算法实现（secp256k1）"""

    def __init__(self):
        # secp256k1参数
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0
        self.b = 7
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.G = Point(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )

    def mod_inverse(self, a: int, m: int) -> int:
        """计算模逆"""
        if a < 0:
            a = (a % m + m) % m
        g, x, _ = self.extended_gcd(a, m)
        if g == 1:
            return x % m
        raise Exception('模逆不存在')

    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """扩展欧几里得算法"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def point_add(self, p1: Point, p2: Point) -> Point:
        """椭圆曲线点加法"""
        if p1.x is None:
            return p2
        if p2.x is None:
            return p1

        if p1.x == p2.x:
            if p1.y == p2.y:
                return self.point_double(p1)
            else:
                return Point(None, None)  # 无穷远点

        # 计算斜率
        s = (p2.y - p1.y) * self.mod_inverse(p2.x - p1.x, self.p) % self.p

        # 计算新点
        x3 = (s * s - p1.x - p2.x) % self.p
        y3 = (s * (p1.x - x3) - p1.y) % self.p

        return Point(x3, y3)

    def point_double(self, p: Point) -> Point:
        """椭圆曲线点倍加"""
        if p.x is None:
            return p

        # 计算斜率
        s = (3 * p.x * p.x + self.a) * self.mod_inverse(2 * p.y, self.p) % self.p

        # 计算新点
        x3 = (s * s - 2 * p.x) % self.p
        y3 = (s * (p.x - x3) - p.y) % self.p

        return Point(x3, y3)

    def scalar_mult(self, k: int, point: Point) -> Point:
        """标量乘法（k * point）"""
        if k == 0:
            return Point(None, None)
        if k == 1:
            return point

        result = Point(None, None)
        addend = point

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1

        return result

    def generate_keypair(self) -> Tuple[int, Point]:
        """生成密钥对"""
        # 生成私钥（随机数）
        private_key = secrets.randbelow(self.n - 1) + 1

        # 计算公钥
        public_key = self.scalar_mult(private_key, self.G)

        return private_key, public_key

    def hash_message(self, message: bytes) -> int:
        """对消息进行SHA-256哈希"""
        hash_bytes = hashlib.sha256(message).digest()
        return int.from_bytes(hash_bytes, 'big')

    def sign(self, message: bytes, private_key: int) -> Tuple[int, int]:
        """数字签名"""
        z = self.hash_message(message)

        while True:
            # 生成随机数k
            k = secrets.randbelow(self.n - 1) + 1

            # 计算r
            point = self.scalar_mult(k, self.G)
            r = point.x % self.n

            if r == 0:
                continue

            # 计算s
            k_inv = self.mod_inverse(k, self.n)
            s = (k_inv * (z + r * private_key)) % self.n

            if s == 0:
                continue

            return r, s

    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Point) -> bool:
        """验证签名"""
        r, s = signature

        # 检查r和s的范围
        if not (1 <= r < self.n) or not (1 <= s < self.n):
            return False

        z = self.hash_message(message)

        # 计算验证参数
        s_inv = self.mod_inverse(s, self.n)
        u1 = (z * s_inv) % self.n
        u2 = (r * s_inv) % self.n

        # 计算验证点
        point = self.point_add(
            self.scalar_mult(u1, self.G),
            self.scalar_mult(u2, public_key)
        )

        if point.x is None:
            return False

        return (point.x % self.n) == r

    def public_key_to_address(self, public_key: Point) -> str:
        # 压缩公钥格式
        if public_key.y % 2 == 0:
            compressed = b'\x02' + public_key.x.to_bytes(32, 'big')
        else:
            compressed = b'\x03' + public_key.x.to_bytes(32, 'big')

        # SHA-256 + RIPEMD-160
        sha256_hash = hashlib.sha256(compressed).digest()

        # 简化：这里只返回公钥哈希的十六进制表示
        return sha256_hash[:20].hex()


def demo():
    """演示ECDSA签名和验证过程"""
    ecdsa = ECDSA()

    # 生成密钥对
    print("=== 密钥生成 ===")
    private_key, public_key = ecdsa.generate_keypair()
    print(f"私钥: {private_key:x}")
    print(f"公钥: {public_key}")

    # 生成地址
    address = ecdsa.public_key_to_address(public_key)
    print(f"地址: {address}")

    # 签名消息
    print("\n=== 数字签名 ===")
    message = b"Hello Bitcoin! This is a test transaction."
    print(f"消息: {message.decode()}")

    signature = ecdsa.sign(message, private_key)
    r, s = signature
    print(f"签名 r: {r:x}")
    print(f"签名 s: {s:x}")

    # 验证签名
    print("\n=== 签名验证 ===")
    is_valid = ecdsa.verify(message, signature, public_key)
    print(f"签名验证结果: {'有效' if is_valid else '无效'}")

    # 测试错误消息
    wrong_message = b"Hello Bitcoin! This is a fake transaction."
    is_valid_wrong = ecdsa.verify(wrong_message, signature, public_key)
    print(f"错误消息验证结果: {'有效' if is_valid_wrong else '无效'}")

    return ecdsa, private_key, public_key, signature


if __name__ == "__main__":
    ecdsa, priv_key, pub_key, sig = demo()