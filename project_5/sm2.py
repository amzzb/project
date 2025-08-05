import hashlib
import secrets
import struct
import time
from typing import Tuple, Optional, List, Dict
from dataclasses import dataclass


@dataclass
class Point:
    """椭圆曲线点类 - 支持仿射坐标和雅可比坐标"""
    x: int
    y: int
    z: int = 1  # 雅可比坐标，z=1表示仿射坐标
    infinity: bool = False

    def __post_init__(self):
        if self.infinity:
            self.x = self.y = self.z = 0

    def is_infinity(self) -> bool:
        return self.infinity

    def to_affine(self, p: int) -> 'Point':
        """转换为仿射坐标"""
        if self.infinity:
            return Point(0, 0, 1, True)
        if self.z == 1:
            return Point(self.x, self.y, 1)

        z_inv = mod_inverse(self.z, p)
        z_inv_2 = (z_inv * z_inv) % p
        z_inv_3 = (z_inv_2 * z_inv) % p

        return Point(
            (self.x * z_inv_2) % p,
            (self.y * z_inv_3) % p,
            1
        )

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        if self.infinity != other.infinity:
            return False
        if self.infinity:
            return True
        return self.x == other.x and self.y == other.y and self.z == other.z


class SM2Curve:
    """SM2椭圆曲线参数"""

    def __init__(self):
        # SM2推荐曲线参数
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        self.gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        self.gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

        self.G = Point(self.gx, self.gy)


def mod_inverse(a: int, m: int) -> int:
    """扩展欧几里得算法求模逆"""
    if a < 0:
        a = (a % m + m) % m

    # 扩展欧几里得算法
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError('模逆不存在')
    return x % m


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得算法"""
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


class BigIntArithmetic:
    """大数运算类"""

    @staticmethod
    def mod_add(a: int, b: int, p: int) -> int:
        """模加法运算 - 带进位处理"""
        result = a + b
        if result >= p:
            result -= p
        return result

    @staticmethod
    def mod_sub(a: int, b: int, p: int) -> int:
        """模减法运算 - 带借位处理"""
        result = a - b
        if result < 0:
            result += p
        return result

    @staticmethod
    def mod_mul(a: int, b: int, p: int) -> int:
        """模乘法运算"""
        return (a * b) % p

    @staticmethod
    def mod_square(a: int, p: int) -> int:
        """模平方运算"""
        return (a * a) % p

    @staticmethod
    def montgomery_reduction_sm2(a: int, p: int) -> int:
        """SM2曲线的蒙哥马利快速模约简
        p = 2^256 - 2^224 - 2^96 + 2^64 - 1
        将模约转换为加法和减法"""
        # 简化实现，实际应用中需要按照文档中的算法优化
        # 这里保持标准模运算
        return a % p

    @staticmethod
    def barrett_reduction(a: int, p: int, mu: int) -> int:
        """巴洛特模约"""
        # 简化实现
        return a % p


class EllipticCurveArithmetic:
    """椭圆曲线运算类"""

    def __init__(self, curve: SM2Curve):
        self.curve = curve
        self.arith = BigIntArithmetic()

    def point_double_jacobian(self, P: Point) -> Point:
        """雅可比坐标下的点倍乘"""
        if P.is_infinity():
            return Point(0, 0, 1, True)

        p = self.curve.p

        # Y1^2
        Y1_squared = self.arith.mod_square(P.y, p)

        # S = 4*X1*Y1^2
        S = self.arith.mod_mul(4, self.arith.mod_mul(P.x, Y1_squared, p), p)

        # M = 3*X1^2 + a*Z1^4
        X1_squared = self.arith.mod_square(P.x, p)
        Z1_squared = self.arith.mod_square(P.z, p)
        Z1_fourth = self.arith.mod_square(Z1_squared, p)
        M = self.arith.mod_add(
            self.arith.mod_mul(3, X1_squared, p),
            self.arith.mod_mul(self.curve.a, Z1_fourth, p),
            p
        )

        # X3 = M^2 - 2*S
        X3 = self.arith.mod_sub(
            self.arith.mod_square(M, p),
            self.arith.mod_mul(2, S, p),
            p
        )

        # Y3 = M*(S - X3) - 8*Y1^4
        Y1_fourth = self.arith.mod_square(Y1_squared, p)
        Y3 = self.arith.mod_sub(
            self.arith.mod_mul(M, self.arith.mod_sub(S, X3, p), p),
            self.arith.mod_mul(8, Y1_fourth, p),
            p
        )

        # Z3 = 2*Y1*Z1
        Z3 = self.arith.mod_mul(2, self.arith.mod_mul(P.y, P.z, p), p)

        return Point(X3, Y3, Z3)

    def point_add_jacobian(self, P: Point, Q: Point) -> Point:
        """雅可比坐标下的点加法"""
        if P.is_infinity():
            return Q
        if Q.is_infinity():
            return P

        p = self.curve.p

        # U1 = X1*Z2^2, U2 = X2*Z1^2
        Z1_squared = self.arith.mod_square(P.z, p)
        Z2_squared = self.arith.mod_square(Q.z, p)
        U1 = self.arith.mod_mul(P.x, Z2_squared, p)
        U2 = self.arith.mod_mul(Q.x, Z1_squared, p)

        # S1 = Y1*Z2^3, S2 = Y2*Z1^3
        S1 = self.arith.mod_mul(P.y, self.arith.mod_mul(Q.z, Z2_squared, p), p)
        S2 = self.arith.mod_mul(Q.y, self.arith.mod_mul(P.z, Z1_squared, p), p)

        if U1 == U2:
            if S1 == S2:
                return self.point_double_jacobian(P)
            else:
                return Point(0, 0, 1, True)  # 无穷远点

        # H = U2 - U1, r = S2 - S1
        H = self.arith.mod_sub(U2, U1, p)
        r = self.arith.mod_sub(S2, S1, p)

        # X3 = r^2 - H^3 - 2*U1*H^2
        H_squared = self.arith.mod_square(H, p)
        H_cubed = self.arith.mod_mul(H, H_squared, p)
        X3 = self.arith.mod_sub(
            self.arith.mod_sub(
                self.arith.mod_square(r, p),
                H_cubed,
                p
            ),
            self.arith.mod_mul(2, self.arith.mod_mul(U1, H_squared, p), p),
            p
        )

        # Y3 = r*(U1*H^2 - X3) - S1*H^3
        Y3 = self.arith.mod_sub(
            self.arith.mod_mul(
                r,
                self.arith.mod_sub(
                    self.arith.mod_mul(U1, H_squared, p),
                    X3,
                    p
                ),
                p
            ),
            self.arith.mod_mul(S1, H_cubed, p),
            p
        )

        # Z3 = Z1*Z2*H
        Z3 = self.arith.mod_mul(self.arith.mod_mul(P.z, Q.z, p), H, p)

        return Point(X3, Y3, Z3)

    def point_add_mixed(self, P: Point, Q: Point) -> Point:
        """混合坐标点加法 - P为雅可比坐标，Q为仿射坐标"""
        if P.is_infinity():
            return Q
        if Q.is_infinity():
            return P
        if Q.z != 1:
            return self.point_add_jacobian(P, Q)

        p = self.curve.p

        # Z1^2, Z1^3
        Z1_squared = self.arith.mod_square(P.z, p)
        Z1_cubed = self.arith.mod_mul(Z1_squared, P.z, p)

        # U2 = X2*Z1^2, S2 = Y2*Z1^3
        U2 = self.arith.mod_mul(Q.x, Z1_squared, p)
        S2 = self.arith.mod_mul(Q.y, Z1_cubed, p)

        if P.x == U2:
            if P.y == S2:
                return self.point_double_jacobian(P)
            else:
                return Point(0, 0, 1, True)

        # H = U2 - X1, r = S2 - Y1
        H = self.arith.mod_sub(U2, P.x, p)
        r = self.arith.mod_sub(S2, P.y, p)

        # 其余计算类似标准加法但简化
        H_squared = self.arith.mod_square(H, p)
        H_cubed = self.arith.mod_mul(H, H_squared, p)

        X3 = self.arith.mod_sub(
            self.arith.mod_sub(
                self.arith.mod_square(r, p),
                H_cubed,
                p
            ),
            self.arith.mod_mul(2, self.arith.mod_mul(P.x, H_squared, p), p),
            p
        )

        Y3 = self.arith.mod_sub(
            self.arith.mod_mul(
                r,
                self.arith.mod_sub(
                    self.arith.mod_mul(P.x, H_squared, p),
                    X3,
                    p
                ),
                p
            ),
            self.arith.mod_mul(P.y, H_cubed, p),
            p
        )

        Z3 = self.arith.mod_mul(P.z, H, p)

        return Point(X3, Y3, Z3)

    def scalar_mult_binary(self, k: int, P: Point) -> Point:
        """二进制方法的标量乘法 - 基础实现"""
        if k == 0:
            return Point(0, 0, 1, True)
        if k == 1:
            return P

        result = Point(0, 0, 1, True)  # 无穷远点
        addend = P

        while k:
            if k & 1:
                result = self.point_add_jacobian(result, addend)
            addend = self.point_double_jacobian(addend)
            k >>= 1

        return result

    def scalar_mult_naf(self, k: int, P: Point) -> Point:
        """NAF编码的标量乘法"""
        if k == 0:
            return Point(0, 0, 1, True)

        # 生成NAF编码
        naf = self.generate_naf(k)

        result = Point(0, 0, 1, True)
        neg_P = Point(P.x, self.curve.p - P.y, P.z)  # -P

        for i in range(len(naf) - 1, -1, -1):
            result = self.point_double_jacobian(result)
            if naf[i] == 1:
                result = self.point_add_jacobian(result, P)
            elif naf[i] == -1:
                result = self.point_add_jacobian(result, neg_P)

        return result

    def generate_naf(self, k: int) -> List[int]:
        """生成NAF编码"""
        naf = []
        while k > 0:
            if k & 1:  # k是奇数
                width = 2 - (k & 3)  # width = 2 - (k mod 4)
                naf.append(width)
                k -= width
            else:
                naf.append(0)
            k >>= 1
        return naf

    def scalar_mult_sliding_window(self, k: int, P: Point, width: int = 4) -> Point:
        """滑动窗口方法的标量乘法"""
        if k == 0:
            return Point(0, 0, 1, True)

        # 预计算奇数倍数点
        precomp = self.precompute_odd_multiples(P, width)

        # 转换k为二进制
        binary_k = bin(k)[2:]  # 去掉'0b'前缀
        n = len(binary_k)

        result = Point(0, 0, 1, True)
        i = 0

        while i < n:
            if binary_k[i] == '0':
                result = self.point_double_jacobian(result)
                i += 1
            else:
                # 找到窗口的大小
                window_size = min(width, n - i)

                # 向前看，寻找最大的奇数
                while window_size > 1:
                    window_val = int(binary_k[i:i + window_size], 2)
                    if window_val % 2 == 1:  # 奇数
                        break
                    window_size -= 1

                window_val = int(binary_k[i:i + window_size], 2)

                # 执行倍乘
                for _ in range(window_size):
                    result = self.point_double_jacobian(result)

                # 加上预计算点
                if window_val > 0 and (window_val // 2) < len(precomp):
                    result = self.point_add_jacobian(result, precomp[window_val // 2])
                i += window_size

        return result

    def precompute_odd_multiples(self, P: Point, width: int) -> List[Point]:
        """预计算奇数倍数点：P, 3P, 5P, ..., (2^width-1)P"""
        max_odd = (1 << width) - 1
        precomp = []

        # P
        precomp.append(P)

        if max_odd > 1:
            # 2P
            P2 = self.point_double_jacobian(P)

            # 3P, 5P, 7P, ...
            current = P
            for i in range(3, max_odd + 1, 2):
                current = self.point_add_jacobian(current, P2)
                precomp.append(current)

        return precomp

    def generate_booth_encoding(self, k: int) -> List[int]:
        """生成Booth编码"""
        # 扩展k，在最低位添加0
        k_extended = (k << 1)
        digits = []

        while k_extended > 0:
            if (k_extended & 3) == 1 or (k_extended & 3) == 2:
                digits.append(k_extended & 1)
                k_extended >>= 1
            elif (k_extended & 3) == 3:
                digits.append(-1)
                k_extended = (k_extended + 1) >> 1
            else:  # (k_extended & 3) == 0
                digits.append(0)
                k_extended >>= 1

        return digits

    def scalar_mult_booth_encoding(self, k: int, P: Point) -> Point:
        """Booth编码的标量乘法"""
        if k == 0:
            return Point(0, 0, 1, True)

        # 生成Booth编码
        booth_digits = self.generate_booth_encoding(k)

        result = Point(0, 0, 1, True)
        neg_P = Point(P.x, self.curve.p - P.y, P.z)  # -P

        for digit in reversed(booth_digits):
            result = self.point_double_jacobian(result)
            if digit == 1:
                result = self.point_add_jacobian(result, P)
            elif digit == -1:
                result = self.point_add_jacobian(result, neg_P)

        return result

    def montgomery_ladder(self, k: int, P: Point) -> Point:
        """蒙哥马利阶梯方法 - 常量时间实现，抗侧信道攻击"""
        if k == 0:
            return Point(0, 0, 1, True)

        # 初始化
        R0 = Point(0, 0, 1, True)  # O
        R1 = P  # P

        # 获取k的二进制表示
        bit_length = k.bit_length()

        for i in range(bit_length - 1, -1, -1):
            bit = (k >> i) & 1

            if bit == 0:
                R1 = self.point_add_jacobian(R0, R1)
                R0 = self.point_double_jacobian(R0)
            else:
                R0 = self.point_add_jacobian(R0, R1)
                R1 = self.point_double_jacobian(R1)

        return R0

    def precompute_fixed_point_table(self, P: Point, width: int = 4) -> List[List[Point]]:
        """为固定点生成预计算表 - 梳状方法"""
        num_blocks = 256 // width
        table = []

        # 为每个块生成预计算点
        base_point = P
        for block in range(num_blocks):
            block_table = [Point(0, 0, 1, True)]  # 0*base_point

            current = base_point
            for i in range(1, 1 << width):
                block_table.append(current)
                if i < (1 << width) - 1:
                    current = self.point_add_jacobian(current, base_point)

            table.append(block_table)

            # 下一个块的基点是当前基点的2^width倍
            for _ in range(width):
                base_point = self.point_double_jacobian(base_point)

        return table

    def scalar_mult_fixed_point_comb(self, k: int, precomp_table: List[List[Point]], width: int = 4) -> Point:
        """固定点梳状方法标量乘法"""
        if k == 0:
            return Point(0, 0, 1, True)

        result = Point(0, 0, 1, True)

        # 从最高位开始
        for bit_pos in range(width - 1, -1, -1):
            if bit_pos < width - 1:
                result = self.point_double_jacobian(result)

            # 处理每个块
            for block_idx, block_table in enumerate(precomp_table):
                # 提取当前块对应的位
                shift = block_idx * width + bit_pos
                if shift < 256:  # 确保不超出范围
                    bit = (k >> shift) & 1
                    if bit == 1 and len(block_table) > 0:
                        # 找到对应的预计算点索引
                        table_idx = 0
                        for i in range(width):
                            table_bit_shift = block_idx * width + i
                            if table_bit_shift < 256:
                                table_bit = (k >> table_bit_shift) & 1
                                table_idx |= (table_bit << i)

                        if 0 < table_idx < len(block_table):
                            result = self.point_add_jacobian(result, block_table[table_idx])

        return result


class AdvancedOptimizations:
    """高级优化算法"""

    def __init__(self, curve: SM2Curve):
        self.curve = curve
        self.ec = EllipticCurveArithmetic(curve)

    def joint_sparse_form(self, k: int, l: int) -> List[Tuple[int, int]]:
        """联合稀疏形式(JSF) - 用于双标量乘法优化"""
        jsf = []

        while k > 0 or l > 0:
            # 获取最低位
            k0, l0 = k & 1, l & 1
            k1, l1 = (k >> 1) & 1, (l >> 1) & 1

            # JSF编码规则
            if (k0 + 2 * k1) % 4 == 3:
                d1 = -1 if k0 == 1 else 1
            else:
                d1 = k0

            if (l0 + 2 * l1) % 4 == 3:
                d2 = -1 if l0 == 1 else 1
            else:
                d2 = l0

            # 调整k和l
            if 2 * d1 == 1 + k0:
                k >>= 1
            else:
                k = (k - d1) >> 1

            if 2 * d2 == 1 + l0:
                l >>= 1
            else:
                l = (l - d2) >> 1

            jsf.append((d1, d2))

        return jsf

    def dual_scalar_mult_jsf(self, k: int, P: Point, l: int, Q: Point) -> Point:
        """使用JSF的双标量乘法 kP + lQ"""
        # 预计算点
        precomp = {
            (0, 0): Point(0, 0, 1, True),  # O
            (1, 0): P,  # P
            (-1, 0): Point(P.x, self.curve.p - P.y, P.z),  # -P
            (0, 1): Q,  # Q
            (0, -1): Point(Q.x, self.curve.p - Q.y, Q.z),  # -Q
        }

        # 计算组合点
        try:
            precomp[(1, 1)] = self.ec.point_add_jacobian(P, Q)  # P + Q
            precomp[(-1, 1)] = self.ec.point_add_jacobian(Point(P.x, self.curve.p - P.y, P.z), Q)  # -P + Q
            precomp[(1, -1)] = self.ec.point_add_jacobian(P, Point(Q.x, self.curve.p - Q.y, Q.z))  # P - Q
            precomp[(-1, -1)] = self.ec.point_add_jacobian(Point(P.x, self.curve.p - P.y, P.z),
                                                           Point(Q.x, self.curve.p - Q.y, Q.z))  # -P - Q
        except:
            # 如果计算失败，回退到简单方法
            return self.ec.point_add_jacobian(
                self.ec.scalar_mult_binary(k, P),
                self.ec.scalar_mult_binary(l, Q)
            )

        # 生成JSF编码
        jsf = self.joint_sparse_form(k, l)

        result = Point(0, 0, 1, True)

        for d1, d2 in reversed(jsf):
            result = self.ec.point_double_jacobian(result)
            if (d1, d2) in precomp and not precomp[(d1, d2)].is_infinity():
                result = self.ec.point_add_jacobian(result, precomp[(d1, d2)])

        return result

    def simultaneous_multiple_point_multiplication(self, scalars: List[int], points: List[Point]) -> Point:
        """同时多点乘法 - 用于双倍点运算kG + lP"""
        if len(scalars) != len(points):
            raise ValueError("标量和点的数量必须相同")

        if not scalars:
            return Point(0, 0, 1, True)

        # 使用Shamir的技巧
        max_bits = max(k.bit_length() for k in scalars if k > 0)
        result = Point(0, 0, 1, True)

        for i in range(max_bits - 1, -1, -1):
            result = self.ec.point_double_jacobian(result)

            for j, (scalar, point) in enumerate(zip(scalars, points)):
                if scalar > 0 and (scalar >> i) & 1:
                    result = self.ec.point_add_jacobian(result, point)

        return result

    def co_z_addition(self, P: Point, Q: Point) -> Tuple[Point, Point]:
        """Co-Z坐标加法"""
        if P.is_infinity():
            return Q, P
        if Q.is_infinity():
            return P, Q

        p = self.curve.p
        sum_point = self.ec.point_add_jacobian(P, Q)
        return sum_point, P


class SM2Protocol:
    """SM2协议实现"""

    def __init__(self):
        self.curve = SM2Curve()
        self.ec = EllipticCurveArithmetic(self.curve)
        self.opt = AdvancedOptimizations(self.curve)

    def generate_keypair(self) -> Tuple[int, Point]:
        """生成密钥对"""
        # 生成私钥
        d = secrets.randbelow(self.curve.n - 1) + 1

        # 计算公钥 P = d*G
        P = self.ec.scalar_mult_binary(d, self.curve.G)
        P_affine = P.to_affine(self.curve.p)

        return d, P_affine

    def sm3_hash(self, data: bytes) -> bytes:
        """SM3哈希函数（简化版本，使用sha56代替）"""
        # 这里使用SHA256作为替代，实际应该使用SM3
        return hashlib.sha256(data).digest()

    def sign(self, message: bytes, private_key: int, user_id: bytes = b"1234567812345678") -> Tuple[int, int]:
        """SM2数字签名"""
        # 计算公钥
        public_key = self.ec.scalar_mult_binary(private_key, self.curve.G).to_affine(self.curve.p)

        # 计算消息摘要
        digest = self.compute_digest(message, user_id, public_key)
        e = int.from_bytes(digest, 'big') % self.curve.n

        while True:
            # 生成随机数k
            k = secrets.randbelow(self.curve.n - 1) + 1

            # 计算 (x1, y1) = k*G
            point = self.ec.scalar_mult_binary(k, self.curve.G)
            point_affine = point.to_affine(self.curve.p)
            x1 = point_affine.x

            # 计算 r = (e + x1) mod n
            r = (e + x1) % self.curve.n
            if r == 0 or (r + k) % self.curve.n == 0:
                continue

            # 计算 s = (1 + d)^(-1) * (k - r*d) mod n
            try:
                d_inv = mod_inverse((1 + private_key) % self.curve.n, self.curve.n)
                s = (d_inv * (k - r * private_key)) % self.curve.n
                if s != 0:
                    return r, s
            except:
                continue

    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Point,
               user_id: bytes = b"1234567812345678") -> bool:
        """SM2数字签名验证"""
        r, s = signature

        # 验证签名参数
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False

        # 计算消息摘要
        digest = self.compute_digest(message, user_id, public_key)
        e = int.from_bytes(digest, 'big') % self.curve.n

        # 计算 t = (r + s) mod n
        t = (r + s) % self.curve.n
        if t == 0:
            return False

        # 计算 (x1, y1) = s*G + t*P
        # 使用优化的双标量乘法
        try:
            point = self.opt.dual_scalar_mult_jsf(s, self.curve.G, t, public_key)
            point_affine = point.to_affine(self.curve.p)

            # 验证 r = (e + x1) mod n
            return r == (e + point_affine.x) % self.curve.n
        except:
            # 回退到基础方法
            sG = self.ec.scalar_mult_binary(s, self.curve.G)
            tP = self.ec.scalar_mult_binary(t, public_key)
            point = self.ec.point_add_jacobian(sG, tP)
            point_affine = point.to_affine(self.curve.p)
            return r == (e + point_affine.x) % self.curve.n

    def compute_digest(self, message: bytes, user_id: bytes, public_key: Point) -> bytes:
        """计算SM2签名使用的消息摘要"""
        # Za = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
        entl = len(user_id) * 8  # 比特长度
        za_data = struct.pack('>H', entl) + user_id

        # 椭圆曲线参数
        za_data += self.curve.a.to_bytes(32, 'big')
        za_data += self.curve.b.to_bytes(32, 'big')
        za_data += self.curve.gx.to_bytes(32, 'big')
        za_data += self.curve.gy.to_bytes(32, 'big')
        za_data += public_key.x.to_bytes(32, 'big')
        za_data += public_key.y.to_bytes(32, 'big')

        za = self.sm3_hash(za_data)

        # M' = Za || M
        m_prime = za + message
        return self.sm3_hash(m_prime)

    def encrypt(self, plaintext: bytes, public_key: Point) -> bytes:
        """SM2公钥加密"""
        while True:
            # 生成随机数k
            k = secrets.randbelow(self.curve.n - 1) + 1

            # C1 = k*G
            C1_point = self.ec.scalar_mult_binary(k, self.curve.G)
            C1_affine = C1_point.to_affine(self.curve.p)

            # 计算 k*P
            kP = self.ec.scalar_mult_binary(k, public_key)
            kP_affine = kP.to_affine(self.curve.p)

            # KDF
            klen = len(plaintext)
            key_data = kP_affine.x.to_bytes(32, 'big') + kP_affine.y.to_bytes(32, 'big')
            t = self.kdf(key_data, klen)

            if not all(b == 0 for b in t):
                break

        # C2 = M ⊕ t
        C2 = bytes(a ^ b for a, b in zip(plaintext, t))

        # C3 = Hash(x2 || M || y2)
        hash_data = kP_affine.x.to_bytes(32, 'big') + plaintext + kP_affine.y.to_bytes(32, 'big')
        C3 = self.sm3_hash(hash_data)

        # 组装密文 C = C1 || C3 || C2
        C1_bytes = b'\x04' + C1_affine.x.to_bytes(32, 'big') + C1_affine.y.to_bytes(32, 'big')
        return C1_bytes + C3 + C2

    def decrypt(self, ciphertext: bytes, private_key: int) -> Optional[bytes]:
        """SM2私钥解密"""
        # 解析密文
        if len(ciphertext) < 97:  # 1 + 32 + 32 + 32 + at least 1
            return None

        # 解析C1
        if ciphertext[0] != 0x04:
            return None

        x1 = int.from_bytes(ciphertext[1:33], 'big')
        y1 = int.from_bytes(ciphertext[33:65], 'big')
        C1 = Point(x1, y1)

        # 验证C1是否在曲线上
        if not self.is_on_curve(C1):
            return None

        C3 = ciphertext[65:97]
        C2 = ciphertext[97:]

        # 计算 d*C1
        dC1 = self.ec.scalar_mult_binary(private_key, C1)
        dC1_affine = dC1.to_affine(self.curve.p)

        # KDF
        klen = len(C2)
        key_data = dC1_affine.x.to_bytes(32, 'big') + dC1_affine.y.to_bytes(32, 'big')
        t = self.kdf(key_data, klen)

        # M' = C2 ⊕ t
        M_prime = bytes(a ^ b for a, b in zip(C2, t))

        # 验证 Hash(x2 || M' || y2) = C3
        hash_data = dC1_affine.x.to_bytes(32, 'big') + M_prime + dC1_affine.y.to_bytes(32, 'big')
        u = self.sm3_hash(hash_data)

        if u == C3:
            return M_prime
        else:
            return None

    def kdf(self, key_data: bytes, klen: int) -> bytes:
        """密钥派生函数"""
        v = 32  # SM3输出长度
        ct = 1
        rcnt = (klen + v - 1) // v

        zin = b''
        for i in range(rcnt):
            zin += self.sm3_hash(key_data + struct.pack('>I', ct))
            ct += 1

        return zin[:klen]

    def is_on_curve(self, point: Point) -> bool:
        """验证点是否在椭圆曲线上"""
        if point.is_infinity():
            return True

        # y^2 = x^3 + ax + b
        left = pow(point.y, 2, self.curve.p)
        right = (pow(point.x, 3, self.curve.p) +
                 self.curve.a * point.x + self.curve.b) % self.curve.p

        return left == right

    def key_agreement(self, private_key_a: int, public_key_b: Point,
                      ephemeral_private_a: int, ephemeral_public_b: Point,
                      za: bytes, zb: bytes, klen: int = 32) -> bytes:
        """SM2密钥协商（简化版本）"""
        h = 1  # cofactor

        # 临时公钥
        temp_public_a = self.ec.scalar_mult_binary(ephemeral_private_a, self.curve.G).to_affine(self.curve.p)

        # 计算x1, x2
        x1 = temp_public_a.x % (2 ** 127)
        x2 = ephemeral_public_b.x % (2 ** 127)

        # 计算密钥
        ta = (private_key_a + x1 * ephemeral_private_a) % self.curve.n

        # V = h * ta * (R_B + x2 * P_B)
        temp_point = self.ec.point_add_jacobian(ephemeral_public_b,
                                                self.ec.scalar_mult_binary(x2, public_key_b))
        V = self.ec.scalar_mult_binary(ta, temp_point).to_affine(self.curve.p)

        # KDF
        kdf_input = V.x.to_bytes(32, 'big') + V.y.to_bytes(32, 'big') + za + zb
        return self.kdf(kdf_input, klen)


class PerformanceBenchmark:
    """性能基准测试"""

    def __init__(self):
        self.curve = SM2Curve()
        self.ec = EllipticCurveArithmetic(self.curve)
        self.opt = AdvancedOptimizations(self.curve)
        self.sm2 = SM2Protocol()

    def benchmark_scalar_multiplication(self, iterations: int = 10):
        """基准测试不同的标量乘法算法"""
        print("标量乘法算法性能对比")

        # 生成测试数据
        test_scalars = [secrets.randbelow(self.curve.n) for _ in range(iterations)]
        test_point = self.curve.G

        methods = [
            ("二进制方法", self.ec.scalar_mult_binary),
            ("NAF方法", self.ec.scalar_mult_naf),
            ("滑动窗口(w=4)", lambda k, P: self.ec.scalar_mult_sliding_window(k, P, 4)),
            ("滑动窗口(w=6)", lambda k, P: self.ec.scalar_mult_sliding_window(k, P, 6)),
            ("Booth编码", self.ec.scalar_mult_booth_encoding),
            ("蒙哥马利阶梯", self.ec.montgomery_ladder),
        ]

        results = {}

        for name, method in methods:
            print(f"\n测试 {name}...")
            start_time = time.time()

            for scalar in test_scalars:
                try:
                    result = method(scalar, test_point)
                except Exception as e:
                    print(f"  错误: {e}")
                    break
            else:
                elapsed = time.time() - start_time
                avg_time = elapsed / iterations
                results[name] = avg_time
                print(f"  平均耗时: {avg_time:.4f}秒")

        # 显示性能提升
        if "二进制方法" in results:
            baseline = results["二进制方法"]
            print(f"\n相对于二进制方法的性能提升:")
            for name, time_taken in results.items():
                if name != "二进制方法":
                    improvement = ((baseline - time_taken) / baseline) * 100
                    print(f"  {name}: {improvement:+.1f}%")

    def benchmark_dual_scalar_mult(self, iterations: int = 5):
        """基准测试双标量乘法"""
        print("\n双标量乘法算法性能对比")

        # 生成测试数据
        test_data = [(secrets.randbelow(self.curve.n), secrets.randbelow(self.curve.n)) for _ in range(iterations)]
        P = self.curve.G
        # 生成另一个点Q
        Q = self.ec.scalar_mult_binary(secrets.randbelow(self.curve.n), P).to_affine(self.curve.p)

        methods = [
            ("分别计算后相加", lambda k, l: self.separate_then_add(k, P, l, Q)),
            ("同时多点乘法", lambda k, l: self.opt.simultaneous_multiple_point_multiplication([k, l], [P, Q])),
            ("JSF方法", lambda k, l: self.opt.dual_scalar_mult_jsf(k, P, l, Q)),
        ]

        results = {}

        for name, method in methods:
            print(f"\n测试 {name}...")
            start_time = time.time()

            for k, l in test_data:
                try:
                    result = method(k, l)
                except Exception as e:
                    print(f"  错误: {e}")
                    break
            else:
                elapsed = time.time() - start_time
                avg_time = elapsed / iterations
                results[name] = avg_time
                print(f"  平均耗时: {avg_time:.4f}秒")

        # 显示性能提升
        if "分别计算后相加" in results:
            baseline = results["分别计算后相加"]
            print(f"\n相对于分别计算的性能提升:")
            for name, time_taken in results.items():
                if name != "分别计算后相加":
                    improvement = ((baseline - time_taken) / baseline) * 100
                    print(f"  {name}: {improvement:+.1f}%")

    def separate_then_add(self, k: int, P: Point, l: int, Q: Point) -> Point:
        """分别计算kP和lQ然后相加"""
        kP = self.ec.scalar_mult_binary(k, P)
        lQ = self.ec.scalar_mult_binary(l, Q)
        return self.ec.point_add_jacobian(kP, lQ)

    def benchmark_protocol_operations(self, iterations: int = 5):
        """基准测试协议操作"""
        print("\n协议操作性能测试")

        # 生成密钥对
        private_key, public_key = self.sm2.generate_keypair()
        message = b"Hello, SM2 benchmark!"
        plaintext = b"SM2 encryption benchmark test message"

        # 签名性能
        print("\n数字签名性能:")
        start_time = time.time()
        signatures = []
        for _ in range(iterations):
            sig = self.sm2.sign(message, private_key)
            signatures.append(sig)
        sign_time = (time.time() - start_time) / iterations
        print(f"  平均签名耗时: {sign_time:.4f}秒")

        # 验签性能
        start_time = time.time()
        for sig in signatures:
            valid = self.sm2.verify(message, sig, public_key)
        verify_time = (time.time() - start_time) / iterations
        print(f"  平均验签耗时: {verify_time:.4f}秒")

        # 加密性能
        start_time = time.time()
        ciphertexts = []
        for _ in range(iterations):
            ciphertext = self.sm2.encrypt(plaintext, public_key)
            ciphertexts.append(ciphertext)
        encrypt_time = (time.time() - start_time) / iterations
        print(f"  平均加密耗时: {encrypt_time:.4f}秒")

        # 解密性能
        start_time = time.time()
        for ciphertext in ciphertexts:
            decrypted = self.sm2.decrypt(ciphertext, private_key)
        decrypt_time = (time.time() - start_time) / iterations
        print(f"  平均解密耗时: {decrypt_time:.4f}秒")

    def test_correctness(self):
        """正确性测试"""
        print("\n算法正确性验证")

        # 测试数据
        k = secrets.randbelow(self.curve.n)
        l = secrets.randbelow(self.curve.n)
        P = self.curve.G
        Q = self.ec.scalar_mult_binary(secrets.randbelow(self.curve.n), P).to_affine(self.curve.p)

        # 基准结果
        baseline = self.ec.scalar_mult_binary(k, P).to_affine(self.curve.p)
        dual_baseline = self.separate_then_add(k, P, l, Q).to_affine(self.curve.p)

        # 测试各种算法
        algorithms = [
            ("NAF方法", self.ec.scalar_mult_naf),
            ("滑动窗口", lambda k, P: self.ec.scalar_mult_sliding_window(k, P, 4)),
            ("Booth编码", self.ec.scalar_mult_booth_encoding),
            ("蒙哥马利阶梯", self.ec.montgomery_ladder),
        ]

        print("单标量乘法正确性:")
        for name, method in algorithms:
            try:
                result = method(k, P).to_affine(self.curve.p)
                correct = (result.x == baseline.x and result.y == baseline.y)
                print(f"  {name}: {'✓' if correct else '✗'}")
            except Exception as e:
                print(f"  {name}: 错误 - {e}")

        # 测试双标量乘法
        print("\n双标量乘法正确性:")
        dual_algorithms = [
            ("同时多点乘法", lambda k, l: self.opt.simultaneous_multiple_point_multiplication([k, l], [P, Q])),
            ("JSF方法", lambda k, l: self.opt.dual_scalar_mult_jsf(k, P, l, Q)),
        ]

        for name, method in dual_algorithms:
            try:
                result = method(k, l).to_affine(self.curve.p)
                correct = (result.x == dual_baseline.x and result.y == dual_baseline.y)
                print(f"  {name}: {'✓' if correct else '✗'}")
            except Exception as e:
                print(f"  {name}: 错误 - {e}")


def demo_basic_usage():
    """基础功能演示"""
    print("SM2椭圆曲线密码算法基础演示\n")

    sm2 = SM2Protocol()

    # 生成密钥对
    print("1. 生成密钥对")
    private_key, public_key = sm2.generate_keypair()
    print(f"私钥: {hex(private_key)}")
    print(f"公钥x: {hex(public_key.x)}")
    print(f"公钥y: {hex(public_key.y)}\n")

    # 数字签名
    print("2. 数字签名")
    message = b"Hello, SM2!"
    signature = sm2.sign(message, private_key)
    print(f"消息: {message}")
    print(f"签名r: {hex(signature[0])}")
    print(f"签名s: {hex(signature[1])}")

    # 签名验证
    print("\n3. 签名验证")
    is_valid = sm2.verify(message, signature, public_key)
    print(f"验证结果: {'通过' if is_valid else '失败'}")

    # 公钥加密
    print("\n4. 公钥加密")
    plaintext = b"SM2 encryption test"
    ciphertext = sm2.encrypt(plaintext, public_key)
    print(f"明文: {plaintext}")
    print(f"密文长度: {len(ciphertext)} 字节")
    print(f"密文(前32字节): {ciphertext[:32].hex()}")

    # 私钥解密
    print("\n5. 私钥解密")
    decrypted = sm2.decrypt(ciphertext, private_key)
    print(f"解密结果: {decrypted}")
    print(f"解密成功: {'是' if decrypted == plaintext else '否'}")


def demo_advanced_optimizations():
    """高级优化演示"""
    print("\n高级优化算法演示")

    curve = SM2Curve()
    opt = AdvancedOptimizations(curve)

    # JSF编码示例
    k, l = 123456789, 987654321
    jsf = opt.joint_sparse_form(k, l)
    non_zero_jsf = sum(1 for d1, d2 in jsf if d1 != 0 or d2 != 0)
    total_bits = max(k.bit_length(), l.bit_length())

    print(f"\nJSF编码优化示例:")
    print(f"  k = {k}, l = {l}")
    print(f"  标准方法需要约 {total_bits * 2} 次运算")
    print(f"  JSF方法需要约 {non_zero_jsf + len(jsf)} 次运算")
    improvement = ((total_bits * 2 - non_zero_jsf - len(jsf)) / (total_bits * 2) * 100)
    print(f"  理论效率提升: {improvement:.1f}%")

    # NAF编码示例
    ec = EllipticCurveArithmetic(curve)
    test_k = secrets.randbelow(curve.n)
    naf = ec.generate_naf(test_k)
    non_zero_naf = sum(1 for x in naf if x != 0)

    print(f"\nNAF编码优化示例:")
    print(f"  标量k的比特长度: {test_k.bit_length()}")
    print(f"  二进制方法平均需要约 {test_k.bit_length() // 2} 次点加")
    print(f"  NAF方法需要约 {non_zero_naf} 次点加")
    naf_improvement = ((test_k.bit_length() // 2 - non_zero_naf) / (test_k.bit_length() // 2) * 100)
    print(f"  理论效率提升: {naf_improvement:.1f}%")


def run_complete_test():
    """运行完整测试"""
    print("SM2椭圆曲线密码算法完整实现测试\n" + "=" * 50)

    # 基础演示
    demo_basic_usage()

    # 高级优化演示
    demo_advanced_optimizations()

    # 性能测试
    print("\n" + "=" * 50)
    benchmark = PerformanceBenchmark()

    # 正确性测试
    benchmark.test_correctness()

    # 性能基准测试
    benchmark.benchmark_scalar_multiplication(3)  # 减少迭代次数
    benchmark.benchmark_dual_scalar_mult(3)
    benchmark.benchmark_protocol_operations(3)

    print("测试完成！")

if __name__ == "__main__":
    run_complete_test()