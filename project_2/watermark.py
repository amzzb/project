import numpy as np
import cv2
from scipy.fft import dct, idct
from PIL import Image, ImageEnhance
import os
from skimage.metrics import structural_similarity as ssim
import warnings

warnings.filterwarnings('ignore')


class DigitalWatermark:
    def __init__(self, block_size=8, alpha=0.1):
        """
        数字水印类

        Args:
            block_size (int): DCT块大小，默认8x8
            alpha (float): 水印强度参数，默认0.1
        """
        self.block_size = block_size
        self.alpha = alpha

    def _text_to_binary(self, text):
        """将文本转换为二进制"""
        binary = ''.join(format(ord(char), '08b') for char in text)
        return binary

    def _binary_to_text(self, binary):
        """将二进制转换为文本"""
        text = ''
        for i in range(0, len(binary), 8):
            byte = binary[i:i + 8]
            if len(byte) == 8:
                try:
                    text += chr(int(byte, 2))
                except ValueError:
                    text += '?'  # 无法解码的字符用?替代
        return text

    def _dct2(self, block):
        """2D DCT变换"""
        return dct(dct(block.T, norm='ortho').T, norm='ortho')

    def _idct2(self, block):
        """2D IDCT逆变换"""
        return idct(idct(block.T, norm='ortho').T, norm='ortho')

    def _get_watermark_positions(self, height, width, watermark_length):
        """获取水印嵌入位置（中频区域）"""
        positions = []
        blocks_h = height // self.block_size
        blocks_w = width // self.block_size

        # 在每个8x8块的中频位置嵌入水印
        mid_freq_positions = [(2, 3), (3, 2), (4, 1), (1, 4), (3, 4), (4, 3)]

        pos_idx = 0
        for i in range(blocks_h):
            for j in range(blocks_w):
                if pos_idx >= watermark_length:
                    break

                block_start_h = i * self.block_size
                block_start_w = j * self.block_size

                # 选择中频位置
                freq_pos = mid_freq_positions[pos_idx % len(mid_freq_positions)]
                pos_h = block_start_h + freq_pos[0]
                pos_w = block_start_w + freq_pos[1]

                if pos_h < height and pos_w < width:
                    positions.append((pos_h, pos_w, i, j, freq_pos[0], freq_pos[1]))
                    pos_idx += 1

            if pos_idx >= watermark_length:
                break

        return positions[:watermark_length]

    def embed_watermark(self, image_path, watermark_text, output_path=None):
        """
        在图像中嵌入水印
        """
        # 读取图像
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError(f"无法读取图像: {image_path}")

        # 转换为YUV色彩空间，在Y通道嵌入水印
        img_yuv = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
        y_channel = img_yuv[:, :, 0].astype(np.float32)

        # 将水印文本转换为二进制
        watermark_binary = self._text_to_binary(watermark_text)
        watermark_length = len(watermark_binary)

        print(f"水印文本: {watermark_text}")
        print(f"水印二进制长度: {watermark_length}")

        # 获取水印嵌入位置
        positions = self._get_watermark_positions(y_channel.shape[0], y_channel.shape[1], watermark_length)

        if len(positions) < watermark_length:
            raise ValueError(f"图像太小，无法嵌入长度为{watermark_length}的水印")

        # 在DCT域嵌入水印
        watermarked_y = y_channel.copy()

        # 按块处理
        for idx, (pos_h, pos_w, block_i, block_j, freq_h, freq_w) in enumerate(positions):
            # 获取8x8块
            block_start_h = block_i * self.block_size
            block_end_h = min(block_start_h + self.block_size, y_channel.shape[0])
            block_start_w = block_j * self.block_size
            block_end_w = min(block_start_w + self.block_size, y_channel.shape[1])

            block = y_channel[block_start_h:block_end_h, block_start_w:block_end_w]

            if block.shape[0] == self.block_size and block.shape[1] == self.block_size:
                # DCT变换
                dct_block = self._dct2(block)

                # 嵌入水印位
                bit = int(watermark_binary[idx])
                if bit == 1:
                    dct_block[freq_h, freq_w] += self.alpha * abs(dct_block[freq_h, freq_w])
                else:
                    dct_block[freq_h, freq_w] -= self.alpha * abs(dct_block[freq_h, freq_w])

                # IDCT逆变换
                watermarked_block = self._idct2(dct_block)
                watermarked_y[block_start_h:block_end_h, block_start_w:block_end_w] = watermarked_block

        # 重建图像
        img_yuv[:, :, 0] = np.clip(watermarked_y, 0, 255).astype(np.uint8)
        watermarked_img = cv2.cvtColor(img_yuv, cv2.COLOR_YUV2BGR)

        # 保存图像
        if output_path:
            cv2.imwrite(output_path, watermarked_img)
            print(f"水印图像已保存至: {output_path}")

        return watermarked_img, positions

    def extract_watermark(self, watermarked_image_path, positions, expected_length):
        """
        从图像中提取水印
        """
        # 使用兼容中文路径的方法读取图像
        if isinstance(watermarked_image_path, str) and any(ord(char) > 127 for char in watermarked_image_path):
            # 如果路径包含非ASCII字符，使用numpy读取
            img_array = np.fromfile(watermarked_image_path, dtype=np.uint8)
            img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
        else:
            img = cv2.imread(watermarked_image_path)

        if img is None:
            raise ValueError(f"无法读取图像: {watermarked_image_path}")

        # 转换为YUV色彩空间
        img_yuv = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
        y_channel = img_yuv[:, :, 0].astype(np.float32)

        # 提取水印
        extracted_bits = []

        for idx, (pos_h, pos_w, block_i, block_j, freq_h, freq_w) in enumerate(positions[:expected_length]):
            # 获取8x8块
            block_start_h = block_i * self.block_size
            block_end_h = min(block_start_h + self.block_size, y_channel.shape[0])
            block_start_w = block_j * self.block_size
            block_end_w = min(block_start_w + self.block_size, y_channel.shape[1])

            block = y_channel[block_start_h:block_end_h, block_start_w:block_end_w]

            if block.shape[0] == self.block_size and block.shape[1] == self.block_size:
                # DCT变换
                dct_block = self._dct2(block)

                # 提取水印位（基于DCT系数的符号）
                coeff = dct_block[freq_h, freq_w]
                # 使用改进的提取策略
                if coeff > 0:
                    extracted_bits.append('1')
                else:
                    extracted_bits.append('0')

        # 将二进制转换为文本
        extracted_binary = ''.join(extracted_bits)
        extracted_text = self._binary_to_text(extracted_binary)

        return extracted_text, extracted_binary

    def calculate_correlation(self, original_binary, extracted_binary):
        """计算相关系数"""
        if len(original_binary) != len(extracted_binary):
            min_len = min(len(original_binary), len(extracted_binary))
            original_binary = original_binary[:min_len]
            extracted_binary = extracted_binary[:min_len]

        original_array = np.array([int(bit) for bit in original_binary])
        extracted_array = np.array([int(bit) for bit in extracted_binary])

        correlation = np.corrcoef(original_array, extracted_array)[0, 1]
        return correlation if not np.isnan(correlation) else 0


class RobustnessTest:
    """鲁棒性测试类"""

    @staticmethod
    def flip_horizontal(image):
        """水平翻转"""
        return cv2.flip(image, 1)

    @staticmethod
    def flip_vertical(image):
        """垂直翻转"""
        return cv2.flip(image, 0)

    @staticmethod
    def translate(image, dx=10, dy=10):
        """平移"""
        rows, cols = image.shape[:2]
        M = np.float32([[1, 0, dx], [0, 1, dy]])
        return cv2.warpAffine(image, M, (cols, rows))

    @staticmethod
    def crop(image, x=50, y=50, w=None, h=None):
        """裁剪"""
        if w is None:
            w = max(image.shape[1] - 100, image.shape[1] // 2)
        if h is None:
            h = max(image.shape[0] - 100, image.shape[0] // 2)
        return image[y:y + h, x:x + w]

    @staticmethod
    def adjust_contrast(image, factor=1.5):
        """调整对比度"""
        try:
            # 转换为PIL图像进行对比度调整
            pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
            enhancer = ImageEnhance.Contrast(pil_image)
            enhanced = enhancer.enhance(factor)
            return cv2.cvtColor(np.array(enhanced), cv2.COLOR_RGB2BGR)
        except Exception as e:
            print(f"对比度调整失败: {e}")
            return image

    @staticmethod
    def adjust_brightness(image, factor=1.2):
        """调整亮度"""
        try:
            pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
            enhancer = ImageEnhance.Brightness(pil_image)
            enhanced = enhancer.enhance(factor)
            return cv2.cvtColor(np.array(enhanced), cv2.COLOR_RGB2BGR)
        except Exception as e:
            print(f"亮度调整失败: {e}")
            return image

    @staticmethod
    def add_noise(image, noise_level=25):
        """添加高斯噪声"""
        noise = np.random.normal(0, noise_level, image.shape).astype(np.int16)
        noisy_image = image.astype(np.int16) + noise
        return np.clip(noisy_image, 0, 255).astype(np.uint8)

    @staticmethod
    def rotate(image, angle=5):
        """旋转"""
        rows, cols = image.shape[:2]
        center = (cols // 2, rows // 2)
        M = cv2.getRotationMatrix2D(center, angle, 1)
        return cv2.warpAffine(image, M, (cols, rows))

    @staticmethod
    def jpeg_compression(image, quality=80):
        """JPEG压缩"""
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
        _, encoded_img = cv2.imencode('.jpg', image, encode_param)
        decoded_img = cv2.imdecode(encoded_img, cv2.IMREAD_COLOR)
        return decoded_img


def create_test_image(path="test_image.jpg", size=(512, 512)):
    """创建测试图像"""
    print(f"创建测试图像: {path}")
    # 创建一个彩色测试图像
    img = np.zeros((size[0], size[1], 3), dtype=np.uint8)

    # 添加渐变背景
    for i in range(size[0]):
        for j in range(size[1]):
            img[i, j] = [i % 256, j % 256, (i + j) % 256]

    # 添加一些几何图形
    cv2.rectangle(img, (100, 100), (200, 200), (255, 0, 0), -1)
    cv2.circle(img, (350, 350), 80, (0, 255, 0), -1)
    cv2.line(img, (0, 0), (size[1], size[0]), (0, 0, 255), 5)

    cv2.imwrite(path, img)
    return path


def safe_imwrite(filename, image):
    try:
        # 先尝试直接保存
        cv2.imwrite(filename, image)
    except:
        # 如果失败，使用编码方式保存
        ext = os.path.splitext(filename)[1]
        encode_param = []
        if ext.lower() == '.jpg' or ext.lower() == '.jpeg':
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 95]

        _, encoded_img = cv2.imencode(ext, image, encode_param)
        with open(filename, 'wb') as f:
            f.write(encoded_img.tobytes())


def run_simple_demo():
    
    print("=== 数字水印演示 ===\n")

    # 创建测试图像
    test_image_path = create_test_image()

    # 初始化水印系统
    watermark_system = DigitalWatermark(alpha=0.15)
    robustness_test = RobustnessTest()

    # 要嵌入的水印信息
    watermark_text = "TEST2024"
    print(f"原始水印文本: {watermark_text}")

    try:
        # 1. 嵌入水印
        print("\n1. 嵌入水印...")
        watermarked_img, positions = watermark_system.embed_watermark(
            test_image_path,
            watermark_text,
            "watermarked_simple.jpg"
        )
        original_binary = watermark_system._text_to_binary(watermark_text)
        print("水印嵌入成功！")

        # 2. 直接提取水印
        print("\n2. 直接提取水印...")
        extracted_text, extracted_binary = watermark_system.extract_watermark(
            "watermarked_simple.jpg",
            positions,
            len(original_binary)
        )
        correlation = watermark_system.calculate_correlation(original_binary, extracted_binary)
        print(f"提取的水印文本: '{extracted_text}'")
        print(f"相关系数: {correlation:.4f}")

        # 3. 简单鲁棒性测试 - 使用英文文件名
        print("\n3. 鲁棒性测试...")

        tests = [
            ("JPEG压缩", "jpeg_compression", lambda img: robustness_test.jpeg_compression(img, 70)),
            ("高斯噪声", "gaussian_noise", lambda img: robustness_test.add_noise(img, 20)),
            ("对比度调整", "contrast_adjust", lambda img: robustness_test.adjust_contrast(img, 1.3)),
        ]

        for test_name, test_id, test_func in tests:
            try:
                print(f"\n测试: {test_name}")
                attacked_img = test_func(watermarked_img.copy())
                attacked_path = f"attacked_{test_id}.jpg"
                safe_imwrite(attacked_path, attacked_img)

                extracted_text, extracted_binary = watermark_system.extract_watermark(
                    attacked_path, positions, len(original_binary)
                )
                correlation = watermark_system.calculate_correlation(original_binary, extracted_binary)

                print(f"  提取文本: '{extracted_text}'")
                print(f"  相关系数: {correlation:.4f}")

            except Exception as e:
                print(f"  测试失败: {e}")

        print("\n=== 演示完成 ===")
        print("生成的文件:")
        print("- test_image.jpg: 原始测试图像")
        print("- watermarked_simple.jpg: 嵌入水印后的图像")
        print("- attacked_*.jpg: 各种攻击后的图像")

    except Exception as e:
        print(f"演示过程中出错: {e}")


if __name__ == "__main__":
    run_simple_demo()