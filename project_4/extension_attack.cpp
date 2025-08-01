#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <cassert>
#include <sstream>

class SM3LengthExtension {
private:
    // SM3初始值
    static constexpr uint32_t IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    // 常量Tj
    static constexpr uint32_t T1 = 0x79cc4519;
    static constexpr uint32_t T2 = 0x7a879d8a;

public:
    // 标准SM3哈希计算
    std::vector<uint8_t> sm3_hash(const std::vector<uint8_t>& message);

    // 从指定状态开始的SM3计算（用于长度扩展攻击）
    std::vector<uint8_t> sm3_hash_from_state(
        const std::vector<uint8_t>& message,
        const std::vector<uint32_t>& initial_state,
        uint64_t processed_length
    );

    // 长度扩展攻击核心函数
    struct LengthExtensionResult {
        std::vector<uint8_t> extended_message;
        std::vector<uint8_t> new_hash;
        std::vector<uint8_t> padding;
    };

    LengthExtensionResult length_extension_attack(
        const std::vector<uint8_t>& known_hash,
        size_t original_message_length,
        const std::vector<uint8_t>& extension
    );

    // 验证长度扩展攻击
    void demonstrate_attack();

    // MAC绕过攻击演示
    void demonstrate_mac_bypass();

    // 工具函数
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
    static std::vector<uint32_t> hash_to_state(const std::vector<uint8_t>& hash);

private:
    // SM3基础函数
    static inline uint32_t ROTL32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t P0(uint32_t x) {
        return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
    }

    static inline uint32_t P1(uint32_t x) {
        return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
    }

    static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
    }

    static inline uint32_t bswap32(uint32_t x) {
        return ((x & 0xff000000) >> 24) |
            ((x & 0x00ff0000) >> 8) |
            ((x & 0x0000ff00) << 8) |
            ((x & 0x000000ff) << 24);
    }

    // SM3填充函数
    std::vector<uint8_t> sm3_padding(size_t message_length);

    // 消息扩展
    void message_expansion(const uint32_t* B, uint32_t* W, uint32_t* W_prime);

    // 压缩函数
    void compression(uint32_t* V, const uint32_t* W, const uint32_t* W_prime);

    // 完整的填充和处理
    std::vector<uint8_t> apply_padding(const std::vector<uint8_t>& message);
};

//SM3基础实现

std::vector<uint8_t> SM3LengthExtension::sm3_hash(const std::vector<uint8_t>& message) {
    std::vector<uint8_t> padded_msg = apply_padding(message);

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    // 处理每个512位分组
    for (size_t i = 0; i < padded_msg.size(); i += 64) {
        uint32_t B[16];
        for (int j = 0; j < 16; j++) {
            memcpy(&B[j], &padded_msg[i + j * 4], 4);
            B[j] = bswap32(B[j]);
        }

        uint32_t W[68], W_prime[64];
        message_expansion(B, W, W_prime);
        compression(V, W, W_prime);
    }

    // 输出最终结果
    std::vector<uint8_t> result(32);
    for (int i = 0; i < 8; i++) {
        uint32_t val = bswap32(V[i]);
        memcpy(&result[i * 4], &val, 4);
    }

    return result;
}

std::vector<uint8_t> SM3LengthExtension::sm3_hash_from_state(
    const std::vector<uint8_t>& message,
    const std::vector<uint32_t>& initial_state,
    uint64_t processed_length
) {
    // 计算新的总长度
    uint64_t total_length = processed_length + message.size();

    // 应用填充
    std::vector<uint8_t> padded_msg = message;
    std::vector<uint8_t> padding = sm3_padding(total_length);
    padded_msg.insert(padded_msg.end(), padding.begin(), padding.end());

    uint32_t V[8];
    for (int i = 0; i < 8; i++) {
        V[i] = initial_state[i];
    }

    // 处理每个512位分组
    for (size_t i = 0; i < padded_msg.size(); i += 64) {
        uint32_t B[16];
        for (int j = 0; j < 16; j++) {
            memcpy(&B[j], &padded_msg[i + j * 4], 4);
            B[j] = bswap32(B[j]);
        }

        uint32_t W[68], W_prime[64];
        message_expansion(B, W, W_prime);
        compression(V, W, W_prime);
    }

    // 输出最终结果
    std::vector<uint8_t> result(32);
    for (int i = 0; i < 8; i++) {
        uint32_t val = bswap32(V[i]);
        memcpy(&result[i * 4], &val, 4);
    }

    return result;
}

void SM3LengthExtension::message_expansion(const uint32_t* B, uint32_t* W, uint32_t* W_prime) {
    // 复制前16个字
    for (int j = 0; j < 16; j++) {
        W[j] = B[j];
    }

    // 扩展剩余52个字
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
    }

    // 生成W'
    for (int j = 0; j < 64; j++) {
        W_prime[j] = W[j] ^ W[j + 4];
    }
}

void SM3LengthExtension::compression(uint32_t* V, const uint32_t* W, const uint32_t* W_prime) {
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t Tj = (j < 16) ? T1 : T2;
        uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Tj, j % 32), 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W_prime[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

std::vector<uint8_t> SM3LengthExtension::apply_padding(const std::vector<uint8_t>& message) {
    uint64_t bit_len = message.size() * 8;
    size_t padding_len = (448 - (bit_len + 1) % 512 + 512) % 512;
    size_t total_len = message.size() + 1 + padding_len / 8 + 8;

    std::vector<uint8_t> padded(total_len);

    // 复制原始消息
    memcpy(padded.data(), message.data(), message.size());

    // 添加'1'位
    padded[message.size()] = 0x80;

    // 添加0填充
    for (size_t i = message.size() + 1; i < total_len - 8; i++) {
        padded[i] = 0;
    }

    // 添加长度（大端序）
    for (int i = 0; i < 8; i++) {
        padded[total_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xff;
    }

    return padded;
}

std::vector<uint8_t> SM3LengthExtension::sm3_padding(size_t message_length) {
    uint64_t bit_len = message_length * 8;
    size_t padding_len = (448 - (bit_len + 1) % 512 + 512) % 512;
    size_t total_padding_bytes = 1 + padding_len / 8 + 8;

    std::vector<uint8_t> padding(total_padding_bytes);

    // 添加'1'位
    padding[0] = 0x80;

    // 添加0填充
    for (size_t i = 1; i < total_padding_bytes - 8; i++) {
        padding[i] = 0;
    }

    // 添加长度（大端序）
    for (int i = 0; i < 8; i++) {
        padding[total_padding_bytes - 8 + i] = (bit_len >> (56 - i * 8)) & 0xff;
    }

    return padding;
}

//长度扩展攻击实现

SM3LengthExtension::LengthExtensionResult SM3LengthExtension::length_extension_attack(
    const std::vector<uint8_t>& known_hash,
    size_t original_message_length,
    const std::vector<uint8_t>& extension
) {
    LengthExtensionResult result;

    // 1. 计算原始消息的填充
    result.padding = sm3_padding(original_message_length);

    // 2. 构造扩展消息 = 原始填充 + 扩展内容
    result.extended_message = result.padding;
    result.extended_message.insert(result.extended_message.end(), extension.begin(), extension.end());

    // 3. 将已知哈希值转换为内部状态
    std::vector<uint32_t> state = hash_to_state(known_hash);

    // 4. 计算扩展后的新哈希值
    // 总的已处理长度 = 原始消息长度 + 填充长度
    uint64_t processed_length = original_message_length + result.padding.size();

    result.new_hash = sm3_hash_from_state(extension, state, processed_length);

    return result;
}

//工具函数

std::vector<uint8_t> SM3LengthExtension::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byte_str.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

std::string SM3LengthExtension::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (uint8_t byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

std::vector<uint32_t> SM3LengthExtension::hash_to_state(const std::vector<uint8_t>& hash) {
    std::vector<uint32_t> state(8);
    for (int i = 0; i < 8; i++) {
        memcpy(&state[i], &hash[i * 4], 4);
        state[i] = bswap32(state[i]);
    }
    return state;
}

//攻击演示

void SM3LengthExtension::demonstrate_attack() {
    std::cout << "=== SM3长度扩展攻击演示 ===" << std::endl << std::endl;

    // 原始消息（攻击者不知道具体内容，但知道长度）
    std::string secret = "my_secret_key";
    std::string known_message = "user=admin&role=user";
    std::vector<uint8_t> original_msg(secret.begin(), secret.end());
    original_msg.insert(original_msg.end(), known_message.begin(), known_message.end());

    std::cout << "1. 原始场景:" << std::endl;
    std::cout << "   密钥: \"" << secret << "\"" << std::endl;
    std::cout << "   已知消息: \"" << known_message << "\"" << std::endl;
    std::cout << "   完整消息: \"" << std::string(original_msg.begin(), original_msg.end()) << "\"" << std::endl;
    std::cout << "   消息长度: " << original_msg.size() << " 字节" << std::endl;

    // 计算原始哈希
    std::vector<uint8_t> original_hash = sm3_hash(original_msg);
    std::cout << "   原始哈希: " << bytes_to_hex(original_hash) << std::endl << std::endl;

    // 攻击者想要添加的恶意载荷
    std::string malicious_extension = "&role=admin";
    std::vector<uint8_t> extension(malicious_extension.begin(), malicious_extension.end());

    std::cout << "2. 攻击者目标:" << std::endl;
    std::cout << "   想要添加: \"" << malicious_extension << "\"" << std::endl;
    std::cout << "   攻击者已知: 原始哈希值和消息长度" << std::endl;
    std::cout << "   攻击者未知: 密钥内容" << std::endl << std::endl;

    // 执行长度扩展攻击
    std::cout << "3. 执行长度扩展攻击:" << std::endl;
    LengthExtensionResult attack_result = length_extension_attack(
        original_hash,
        original_msg.size(),
        extension
    );

    std::cout << "   计算出的填充: " << bytes_to_hex(attack_result.padding) << std::endl;
    std::cout << "   填充长度: " << attack_result.padding.size() << " 字节" << std::endl;
    std::cout << "   扩展消息: " << bytes_to_hex(attack_result.extended_message) << std::endl;
    std::cout << "   攻击者计算的新哈希: " << bytes_to_hex(attack_result.new_hash) << std::endl << std::endl;

    // 验证攻击是否成功
    std::cout << "4. 验证攻击结果:" << std::endl;

    // 构造实际的完整消息进行验证
    std::vector<uint8_t> actual_extended_msg = original_msg;
    actual_extended_msg.insert(actual_extended_msg.end(),
        attack_result.padding.begin(),
        attack_result.padding.end());
    actual_extended_msg.insert(actual_extended_msg.end(),
        extension.begin(),
        extension.end());

    std::vector<uint8_t> actual_hash = sm3_hash(actual_extended_msg);

    std::cout << "   实际扩展后的消息结构:" << std::endl;
    std::cout << "   \"" << secret << "\" + \"" << known_message << "\" + 填充 + \"" << malicious_extension << "\"" << std::endl;
    std::cout << "   实际计算的哈希: " << bytes_to_hex(actual_hash) << std::endl;

    bool attack_successful = (attack_result.new_hash == actual_hash);
    std::cout << "   攻击结果: " << (attack_successful ? "成功!" : "失败!") << std::endl << std::endl;

    if (attack_successful) {
        std::cout << "[攻击成功] 长度扩展攻击成功!" << std::endl;
        std::cout << "   攻击者在不知道密钥的情况下，成功计算出了扩展消息的哈希值。" << std::endl;
    }
}

void SM3LengthExtension::demonstrate_mac_bypass() {
    std::cout << std::endl << "=== SM3 MAC绕过攻击演示 ===" << std::endl << std::endl;

    // 模拟一个使用SM3作为MAC的系统
    std::string secret_key = "super_secret_key_123";
    std::string original_data = "action=transfer&amount=100&to=bob";

    std::cout << "1. 合法的MAC系统:" << std::endl;
    std::cout << "   密钥: \"" << secret_key << "\" (长度: " << secret_key.length() << ")" << std::endl;
    std::cout << "   原始数据: \"" << original_data << "\"" << std::endl;

    // 计算合法的MAC: SM3(key || data)
    std::vector<uint8_t> mac_input(secret_key.begin(), secret_key.end());
    mac_input.insert(mac_input.end(), original_data.begin(), original_data.end());

    std::vector<uint8_t> legitimate_mac = sm3_hash(mac_input);
    std::cout << "   合法MAC: " << bytes_to_hex(legitimate_mac) << std::endl << std::endl;

    // 攻击者截获了数据和MAC，想要修改数据
    std::cout << "2. 攻击场景:" << std::endl;
    std::cout << "   攻击者截获: 数据 + MAC" << std::endl;
    std::cout << "   攻击者已知: 密钥长度 (但不知道密钥内容)" << std::endl;
    std::cout << "   攻击者目标: 修改转账金额从100改为999999" << std::endl << std::endl;

    // 执行长度扩展攻击
    std::string malicious_suffix = "&amount=999999";
    std::vector<uint8_t> attack_extension(malicious_suffix.begin(), malicious_suffix.end());

    std::cout << "3. 执行MAC绕过攻击:" << std::endl;
    LengthExtensionResult mac_attack = length_extension_attack(
        legitimate_mac,
        mac_input.size(),
        attack_extension
    );

    std::cout << "   恶意扩展: \"" << malicious_suffix << "\"" << std::endl;
    std::cout << "   伪造的MAC: " << bytes_to_hex(mac_attack.new_hash) << std::endl << std::endl;

    // 构造攻击者提交的数据
    std::cout << "4. 攻击者构造的恶意请求:" << std::endl;
    std::cout << "   数据: \"" << original_data << "\" + 填充 + \"" << malicious_suffix << "\"" << std::endl;
    std::cout << "   MAC: " << bytes_to_hex(mac_attack.new_hash) << std::endl << std::endl;

    // 验证服务器端会如何处理
    std::cout << "5. 服务器端验证:" << std::endl;

    // 服务器重新计算MAC
    std::vector<uint8_t> server_mac_input(secret_key.begin(), secret_key.end());
    server_mac_input.insert(server_mac_input.end(), original_data.begin(), original_data.end());
    server_mac_input.insert(server_mac_input.end(), mac_attack.padding.begin(), mac_attack.padding.end());
    server_mac_input.insert(server_mac_input.end(), attack_extension.begin(), attack_extension.end());

    std::vector<uint8_t> server_computed_mac = sm3_hash(server_mac_input);

    std::cout << "   服务器计算的MAC: " << bytes_to_hex(server_computed_mac) << std::endl;
    std::cout << "   攻击者提供的MAC: " << bytes_to_hex(mac_attack.new_hash) << std::endl;

    bool mac_attack_successful = (server_computed_mac == mac_attack.new_hash);
    std::cout << "   MAC验证结果: " << (mac_attack_successful ? "通过 (危险!)" : "失败 (安全)") << std::endl << std::endl;

    if (mac_attack_successful) {
        std::cout << "[严重漏洞] MAC绕过攻击成功!" << std::endl;
        std::cout << "   攻击者成功伪造了包含恶意数据的有效MAC!" << std::endl;
        std::cout << "   原始转账金额: 100" << std::endl;
        std::cout << "   攻击后金额: 999999" << std::endl << std::endl;

        std::cout << "[防护建议]:" << std::endl;
        std::cout << "   1. 使用HMAC而不是Hash(key||message)" << std::endl;
        std::cout << "   2. 使用抗长度扩展攻击的哈希函数 (如SHA-3)" << std::endl;
        std::cout << "   3. 在MAC计算中包含消息长度字段" << std::endl;
        std::cout << "   4. 使用经过验证的密码学库" << std::endl;
    }
}

//额外演示功能

void demonstrate_advanced_scenarios() {
    std::cout << std::endl << "=== 高级攻击场景演示 ===" << std::endl << std::endl;

    SM3LengthExtension sm3;

    std::cout << "场景1: 文件完整性校验绕过" << std::endl;
    std::cout << "-------------------------------" << std::endl;

    std::string file_header = "FILE_SIGNATURE_2024";
    std::string original_content = "这是一个合法的文件内容。";

    std::cout << "   文件头: \"" << file_header << "\"" << std::endl;
    std::cout << "   原始内容: \"" << original_content << "\"" << std::endl;

    // 计算文件的完整性哈希
    std::vector<uint8_t> file_data(file_header.begin(), file_header.end());
    file_data.insert(file_data.end(), original_content.begin(), original_content.end());

    std::vector<uint8_t> integrity_hash = sm3.sm3_hash(file_data);
    std::cout << "   完整性哈希: " << sm3.bytes_to_hex(integrity_hash) << std::endl;

    // 攻击者想要添加恶意代码
    std::string malicious_code = " 恶意代码已注入";
    std::vector<uint8_t> malicious_extension(malicious_code.begin(), malicious_code.end());

    std::cout << "   恶意载荷: \"" << malicious_code << "\"" << std::endl;

    // 执行长度扩展攻击
    auto attack_result = sm3.length_extension_attack(
        integrity_hash,
        file_data.size(),
        malicious_extension
    );

    std::cout << "   伪造的新哈希: " << sm3.bytes_to_hex(attack_result.new_hash) << std::endl;
    std::cout << "   攻击结果: 攻击者可以在不知道文件头的情况下，" << std::endl;
    std::cout << "            为包含恶意代码的文件生成有效的完整性哈希。" << std::endl << std::endl;

    std::cout << "场景2: 多步骤长度扩展攻击" << std::endl;
    std::cout << "-------------------------------" << std::endl;

    std::string secret = "SECRET";
    std::string msg1 = "step1";
    std::string msg2 = "step2";
    std::string msg3 = "step3";

    // 第一步: 计算基础哈希
    std::vector<uint8_t> base_msg(secret.begin(), secret.end());
    base_msg.insert(base_msg.end(), msg1.begin(), msg1.end());

    std::vector<uint8_t> hash1 = sm3.sm3_hash(base_msg);
    std::cout << "   第1步 - Hash(SECRET||\"step1\"): " << sm3.bytes_to_hex(hash1) << std::endl;

    // 第二步: 基于第一步进行扩展
    std::vector<uint8_t> ext2(msg2.begin(), msg2.end());
    auto result2 = sm3.length_extension_attack(hash1, base_msg.size(), ext2);
    std::cout << "   第2步 - 扩展添加\"step2\": " << sm3.bytes_to_hex(result2.new_hash) << std::endl;

    // 第三步: 基于第二步再次扩展
    size_t total_length_after_step2 = base_msg.size() + result2.padding.size() + ext2.size();
    std::vector<uint8_t> ext3(msg3.begin(), msg3.end());
    auto result3 = sm3.length_extension_attack(result2.new_hash, total_length_after_step2, ext3);
    std::cout << "   第3步 - 扩展添加\"step3\": " << sm3.bytes_to_hex(result3.new_hash) << std::endl;

    std::cout << "   结论: 多步骤攻击演示了长度扩展攻击的可组合性。" << std::endl;
}



int main() {
    std::cout << "SM3长度扩展攻击完整验证程序" << std::endl;
    std::cout << "===============================" << std::endl << std::endl;

    SM3LengthExtension sm3_attack;

    // 基础长度扩展攻击演示
    sm3_attack.demonstrate_attack();

    // MAC绕过攻击演示
    sm3_attack.demonstrate_mac_bypass();

    // 高级攻击场景
    demonstrate_advanced_scenarios();

    return 0;
}
