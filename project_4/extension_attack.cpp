#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <cassert>
#include <sstream>

class SM3LengthExtension {
private:
    // SM3��ʼֵ
    static constexpr uint32_t IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    // ����Tj
    static constexpr uint32_t T1 = 0x79cc4519;
    static constexpr uint32_t T2 = 0x7a879d8a;

public:
    // ��׼SM3��ϣ����
    std::vector<uint8_t> sm3_hash(const std::vector<uint8_t>& message);

    // ��ָ��״̬��ʼ��SM3���㣨���ڳ�����չ������
    std::vector<uint8_t> sm3_hash_from_state(
        const std::vector<uint8_t>& message,
        const std::vector<uint32_t>& initial_state,
        uint64_t processed_length
    );

    // ������չ�������ĺ���
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

    // ��֤������չ����
    void demonstrate_attack();

    // MAC�ƹ�������ʾ
    void demonstrate_mac_bypass();

    // ���ߺ���
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
    static std::vector<uint32_t> hash_to_state(const std::vector<uint8_t>& hash);

private:
    // SM3��������
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

    // SM3��亯��
    std::vector<uint8_t> sm3_padding(size_t message_length);

    // ��Ϣ��չ
    void message_expansion(const uint32_t* B, uint32_t* W, uint32_t* W_prime);

    // ѹ������
    void compression(uint32_t* V, const uint32_t* W, const uint32_t* W_prime);

    // ���������ʹ���
    std::vector<uint8_t> apply_padding(const std::vector<uint8_t>& message);
};

//SM3����ʵ��

std::vector<uint8_t> SM3LengthExtension::sm3_hash(const std::vector<uint8_t>& message) {
    std::vector<uint8_t> padded_msg = apply_padding(message);

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    // ����ÿ��512λ����
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

    // ������ս��
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
    // �����µ��ܳ���
    uint64_t total_length = processed_length + message.size();

    // Ӧ�����
    std::vector<uint8_t> padded_msg = message;
    std::vector<uint8_t> padding = sm3_padding(total_length);
    padded_msg.insert(padded_msg.end(), padding.begin(), padding.end());

    uint32_t V[8];
    for (int i = 0; i < 8; i++) {
        V[i] = initial_state[i];
    }

    // ����ÿ��512λ����
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

    // ������ս��
    std::vector<uint8_t> result(32);
    for (int i = 0; i < 8; i++) {
        uint32_t val = bswap32(V[i]);
        memcpy(&result[i * 4], &val, 4);
    }

    return result;
}

void SM3LengthExtension::message_expansion(const uint32_t* B, uint32_t* W, uint32_t* W_prime) {
    // ����ǰ16����
    for (int j = 0; j < 16; j++) {
        W[j] = B[j];
    }

    // ��չʣ��52����
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
    }

    // ����W'
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

    // ����ԭʼ��Ϣ
    memcpy(padded.data(), message.data(), message.size());

    // ���'1'λ
    padded[message.size()] = 0x80;

    // ���0���
    for (size_t i = message.size() + 1; i < total_len - 8; i++) {
        padded[i] = 0;
    }

    // ��ӳ��ȣ������
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

    // ���'1'λ
    padding[0] = 0x80;

    // ���0���
    for (size_t i = 1; i < total_padding_bytes - 8; i++) {
        padding[i] = 0;
    }

    // ��ӳ��ȣ������
    for (int i = 0; i < 8; i++) {
        padding[total_padding_bytes - 8 + i] = (bit_len >> (56 - i * 8)) & 0xff;
    }

    return padding;
}

//������չ����ʵ��

SM3LengthExtension::LengthExtensionResult SM3LengthExtension::length_extension_attack(
    const std::vector<uint8_t>& known_hash,
    size_t original_message_length,
    const std::vector<uint8_t>& extension
) {
    LengthExtensionResult result;

    // 1. ����ԭʼ��Ϣ�����
    result.padding = sm3_padding(original_message_length);

    // 2. ������չ��Ϣ = ԭʼ��� + ��չ����
    result.extended_message = result.padding;
    result.extended_message.insert(result.extended_message.end(), extension.begin(), extension.end());

    // 3. ����֪��ϣֵת��Ϊ�ڲ�״̬
    std::vector<uint32_t> state = hash_to_state(known_hash);

    // 4. ������չ����¹�ϣֵ
    // �ܵ��Ѵ����� = ԭʼ��Ϣ���� + ��䳤��
    uint64_t processed_length = original_message_length + result.padding.size();

    result.new_hash = sm3_hash_from_state(extension, state, processed_length);

    return result;
}

//���ߺ���

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

//������ʾ

void SM3LengthExtension::demonstrate_attack() {
    std::cout << "=== SM3������չ������ʾ ===" << std::endl << std::endl;

    // ԭʼ��Ϣ�������߲�֪���������ݣ���֪�����ȣ�
    std::string secret = "my_secret_key";
    std::string known_message = "user=admin&role=user";
    std::vector<uint8_t> original_msg(secret.begin(), secret.end());
    original_msg.insert(original_msg.end(), known_message.begin(), known_message.end());

    std::cout << "1. ԭʼ����:" << std::endl;
    std::cout << "   ��Կ: \"" << secret << "\"" << std::endl;
    std::cout << "   ��֪��Ϣ: \"" << known_message << "\"" << std::endl;
    std::cout << "   ������Ϣ: \"" << std::string(original_msg.begin(), original_msg.end()) << "\"" << std::endl;
    std::cout << "   ��Ϣ����: " << original_msg.size() << " �ֽ�" << std::endl;

    // ����ԭʼ��ϣ
    std::vector<uint8_t> original_hash = sm3_hash(original_msg);
    std::cout << "   ԭʼ��ϣ: " << bytes_to_hex(original_hash) << std::endl << std::endl;

    // ��������Ҫ��ӵĶ����غ�
    std::string malicious_extension = "&role=admin";
    std::vector<uint8_t> extension(malicious_extension.begin(), malicious_extension.end());

    std::cout << "2. ������Ŀ��:" << std::endl;
    std::cout << "   ��Ҫ���: \"" << malicious_extension << "\"" << std::endl;
    std::cout << "   ��������֪: ԭʼ��ϣֵ����Ϣ����" << std::endl;
    std::cout << "   ������δ֪: ��Կ����" << std::endl << std::endl;

    // ִ�г�����չ����
    std::cout << "3. ִ�г�����չ����:" << std::endl;
    LengthExtensionResult attack_result = length_extension_attack(
        original_hash,
        original_msg.size(),
        extension
    );

    std::cout << "   ����������: " << bytes_to_hex(attack_result.padding) << std::endl;
    std::cout << "   ��䳤��: " << attack_result.padding.size() << " �ֽ�" << std::endl;
    std::cout << "   ��չ��Ϣ: " << bytes_to_hex(attack_result.extended_message) << std::endl;
    std::cout << "   �����߼�����¹�ϣ: " << bytes_to_hex(attack_result.new_hash) << std::endl << std::endl;

    // ��֤�����Ƿ�ɹ�
    std::cout << "4. ��֤�������:" << std::endl;

    // ����ʵ�ʵ�������Ϣ������֤
    std::vector<uint8_t> actual_extended_msg = original_msg;
    actual_extended_msg.insert(actual_extended_msg.end(),
        attack_result.padding.begin(),
        attack_result.padding.end());
    actual_extended_msg.insert(actual_extended_msg.end(),
        extension.begin(),
        extension.end());

    std::vector<uint8_t> actual_hash = sm3_hash(actual_extended_msg);

    std::cout << "   ʵ����չ�����Ϣ�ṹ:" << std::endl;
    std::cout << "   \"" << secret << "\" + \"" << known_message << "\" + ��� + \"" << malicious_extension << "\"" << std::endl;
    std::cout << "   ʵ�ʼ���Ĺ�ϣ: " << bytes_to_hex(actual_hash) << std::endl;

    bool attack_successful = (attack_result.new_hash == actual_hash);
    std::cout << "   �������: " << (attack_successful ? "�ɹ�!" : "ʧ��!") << std::endl << std::endl;

    if (attack_successful) {
        std::cout << "[�����ɹ�] ������չ�����ɹ�!" << std::endl;
        std::cout << "   �������ڲ�֪����Կ������£��ɹ����������չ��Ϣ�Ĺ�ϣֵ��" << std::endl;
    }
}

void SM3LengthExtension::demonstrate_mac_bypass() {
    std::cout << std::endl << "=== SM3 MAC�ƹ�������ʾ ===" << std::endl << std::endl;

    // ģ��һ��ʹ��SM3��ΪMAC��ϵͳ
    std::string secret_key = "super_secret_key_123";
    std::string original_data = "action=transfer&amount=100&to=bob";

    std::cout << "1. �Ϸ���MACϵͳ:" << std::endl;
    std::cout << "   ��Կ: \"" << secret_key << "\" (����: " << secret_key.length() << ")" << std::endl;
    std::cout << "   ԭʼ����: \"" << original_data << "\"" << std::endl;

    // ����Ϸ���MAC: SM3(key || data)
    std::vector<uint8_t> mac_input(secret_key.begin(), secret_key.end());
    mac_input.insert(mac_input.end(), original_data.begin(), original_data.end());

    std::vector<uint8_t> legitimate_mac = sm3_hash(mac_input);
    std::cout << "   �Ϸ�MAC: " << bytes_to_hex(legitimate_mac) << std::endl << std::endl;

    // �����߽ػ������ݺ�MAC����Ҫ�޸�����
    std::cout << "2. ��������:" << std::endl;
    std::cout << "   �����߽ػ�: ���� + MAC" << std::endl;
    std::cout << "   ��������֪: ��Կ���� (����֪����Կ����)" << std::endl;
    std::cout << "   ������Ŀ��: �޸�ת�˽���100��Ϊ999999" << std::endl << std::endl;

    // ִ�г�����չ����
    std::string malicious_suffix = "&amount=999999";
    std::vector<uint8_t> attack_extension(malicious_suffix.begin(), malicious_suffix.end());

    std::cout << "3. ִ��MAC�ƹ�����:" << std::endl;
    LengthExtensionResult mac_attack = length_extension_attack(
        legitimate_mac,
        mac_input.size(),
        attack_extension
    );

    std::cout << "   ������չ: \"" << malicious_suffix << "\"" << std::endl;
    std::cout << "   α���MAC: " << bytes_to_hex(mac_attack.new_hash) << std::endl << std::endl;

    // ���칥�����ύ������
    std::cout << "4. �����߹���Ķ�������:" << std::endl;
    std::cout << "   ����: \"" << original_data << "\" + ��� + \"" << malicious_suffix << "\"" << std::endl;
    std::cout << "   MAC: " << bytes_to_hex(mac_attack.new_hash) << std::endl << std::endl;

    // ��֤�������˻���δ���
    std::cout << "5. ����������֤:" << std::endl;

    // ���������¼���MAC
    std::vector<uint8_t> server_mac_input(secret_key.begin(), secret_key.end());
    server_mac_input.insert(server_mac_input.end(), original_data.begin(), original_data.end());
    server_mac_input.insert(server_mac_input.end(), mac_attack.padding.begin(), mac_attack.padding.end());
    server_mac_input.insert(server_mac_input.end(), attack_extension.begin(), attack_extension.end());

    std::vector<uint8_t> server_computed_mac = sm3_hash(server_mac_input);

    std::cout << "   �����������MAC: " << bytes_to_hex(server_computed_mac) << std::endl;
    std::cout << "   �������ṩ��MAC: " << bytes_to_hex(mac_attack.new_hash) << std::endl;

    bool mac_attack_successful = (server_computed_mac == mac_attack.new_hash);
    std::cout << "   MAC��֤���: " << (mac_attack_successful ? "ͨ�� (Σ��!)" : "ʧ�� (��ȫ)") << std::endl << std::endl;

    if (mac_attack_successful) {
        std::cout << "[����©��] MAC�ƹ������ɹ�!" << std::endl;
        std::cout << "   �����߳ɹ�α���˰����������ݵ���ЧMAC!" << std::endl;
        std::cout << "   ԭʼת�˽��: 100" << std::endl;
        std::cout << "   ��������: 999999" << std::endl << std::endl;

        std::cout << "[��������]:" << std::endl;
        std::cout << "   1. ʹ��HMAC������Hash(key||message)" << std::endl;
        std::cout << "   2. ʹ�ÿ�������չ�����Ĺ�ϣ���� (��SHA-3)" << std::endl;
        std::cout << "   3. ��MAC�����а�����Ϣ�����ֶ�" << std::endl;
        std::cout << "   4. ʹ�þ�����֤������ѧ��" << std::endl;
    }
}

//������ʾ����

void demonstrate_advanced_scenarios() {
    std::cout << std::endl << "=== �߼�����������ʾ ===" << std::endl << std::endl;

    SM3LengthExtension sm3;

    std::cout << "����1: �ļ�������У���ƹ�" << std::endl;
    std::cout << "-------------------------------" << std::endl;

    std::string file_header = "FILE_SIGNATURE_2024";
    std::string original_content = "����һ���Ϸ����ļ����ݡ�";

    std::cout << "   �ļ�ͷ: \"" << file_header << "\"" << std::endl;
    std::cout << "   ԭʼ����: \"" << original_content << "\"" << std::endl;

    // �����ļ��������Թ�ϣ
    std::vector<uint8_t> file_data(file_header.begin(), file_header.end());
    file_data.insert(file_data.end(), original_content.begin(), original_content.end());

    std::vector<uint8_t> integrity_hash = sm3.sm3_hash(file_data);
    std::cout << "   �����Թ�ϣ: " << sm3.bytes_to_hex(integrity_hash) << std::endl;

    // ��������Ҫ��Ӷ������
    std::string malicious_code = " ���������ע��";
    std::vector<uint8_t> malicious_extension(malicious_code.begin(), malicious_code.end());

    std::cout << "   �����غ�: \"" << malicious_code << "\"" << std::endl;

    // ִ�г�����չ����
    auto attack_result = sm3.length_extension_attack(
        integrity_hash,
        file_data.size(),
        malicious_extension
    );

    std::cout << "   α����¹�ϣ: " << sm3.bytes_to_hex(attack_result.new_hash) << std::endl;
    std::cout << "   �������: �����߿����ڲ�֪���ļ�ͷ������£�" << std::endl;
    std::cout << "            Ϊ�������������ļ�������Ч�������Թ�ϣ��" << std::endl << std::endl;

    std::cout << "����2: �ಽ�賤����չ����" << std::endl;
    std::cout << "-------------------------------" << std::endl;

    std::string secret = "SECRET";
    std::string msg1 = "step1";
    std::string msg2 = "step2";
    std::string msg3 = "step3";

    // ��һ��: ���������ϣ
    std::vector<uint8_t> base_msg(secret.begin(), secret.end());
    base_msg.insert(base_msg.end(), msg1.begin(), msg1.end());

    std::vector<uint8_t> hash1 = sm3.sm3_hash(base_msg);
    std::cout << "   ��1�� - Hash(SECRET||\"step1\"): " << sm3.bytes_to_hex(hash1) << std::endl;

    // �ڶ���: ���ڵ�һ��������չ
    std::vector<uint8_t> ext2(msg2.begin(), msg2.end());
    auto result2 = sm3.length_extension_attack(hash1, base_msg.size(), ext2);
    std::cout << "   ��2�� - ��չ���\"step2\": " << sm3.bytes_to_hex(result2.new_hash) << std::endl;

    // ������: ���ڵڶ����ٴ���չ
    size_t total_length_after_step2 = base_msg.size() + result2.padding.size() + ext2.size();
    std::vector<uint8_t> ext3(msg3.begin(), msg3.end());
    auto result3 = sm3.length_extension_attack(result2.new_hash, total_length_after_step2, ext3);
    std::cout << "   ��3�� - ��չ���\"step3\": " << sm3.bytes_to_hex(result3.new_hash) << std::endl;

    std::cout << "   ����: �ಽ�蹥����ʾ�˳�����չ�����Ŀ�����ԡ�" << std::endl;
}



int main() {
    std::cout << "SM3������չ����������֤����" << std::endl;
    std::cout << "===============================" << std::endl << std::endl;

    SM3LengthExtension sm3_attack;

    // ����������չ������ʾ
    sm3_attack.demonstrate_attack();

    // MAC�ƹ�������ʾ
    sm3_attack.demonstrate_mac_bypass();

    // �߼���������
    demonstrate_advanced_scenarios();

    return 0;
}
