#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <random>
#include <chrono>
#include <cassert>
#include <memory>

// SM3��ϣʵ��
class SM3Hash {
private:
    static constexpr uint32_t IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    static constexpr uint32_t T1 = 0x79cc4519;
    static constexpr uint32_t T2 = 0x7a879d8a;

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

public:
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& message) {
        std::vector<uint8_t> padded_msg = apply_padding(message);

        uint32_t V[8];
        memcpy(V, IV, sizeof(IV));

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

        std::vector<uint8_t> result(32);
        for (int i = 0; i < 8; i++) {
            uint32_t val = bswap32(V[i]);
            memcpy(&result[i * 4], &val, 4);
        }

        return result;
    }

    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        for (uint8_t byte : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        return ss.str();
    }

    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> result;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byte_str = hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byte_str.c_str(), nullptr, 16);
            result.push_back(byte);
        }
        return result;
    }

private:
    static std::vector<uint8_t> apply_padding(const std::vector<uint8_t>& message) {
        uint64_t bit_len = message.size() * 8;
        size_t padding_len = (448 - (bit_len + 1) % 512 + 512) % 512;
        size_t total_len = message.size() + 1 + padding_len / 8 + 8;

        std::vector<uint8_t> padded(total_len);
        memcpy(padded.data(), message.data(), message.size());
        padded[message.size()] = 0x80;

        for (size_t i = message.size() + 1; i < total_len - 8; i++) {
            padded[i] = 0;
        }

        for (int i = 0; i < 8; i++) {
            padded[total_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xff;
        }

        return padded;
    }

    static void message_expansion(const uint32_t* B, uint32_t* W, uint32_t* W_prime) {
        for (int j = 0; j < 16; j++) {
            W[j] = B[j];
        }

        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; j++) {
            W_prime[j] = W[j] ^ W[j + 4];
        }
    }

    static void compression(uint32_t* V, const uint32_t* W, const uint32_t* W_prime) {
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
};

//RFC6962 Merkle��ʵ��

// Ҷ�ӽڵ����ݽṹ
struct LeafEntry {
    std::vector<uint8_t> data;
    std::vector<uint8_t> hash;

    LeafEntry(const std::vector<uint8_t>& d) : data(d) {
        // RFC6962: Ҷ�ӽڵ��ϣ = H(0x00 || leaf_data)
        std::vector<uint8_t> input;
        input.push_back(0x00);
        input.insert(input.end(), data.begin(), data.end());
        hash = SM3Hash::hash(input);
    }

    LeafEntry(const std::string& str) {
        data = std::vector<uint8_t>(str.begin(), str.end());
        std::vector<uint8_t> input;
        input.push_back(0x00);
        input.insert(input.end(), data.begin(), data.end());
        hash = SM3Hash::hash(input);
    }

    std::string to_string() const {
        return std::string(data.begin(), data.end());
    }

    // ��������ıȽϺ���
    bool operator<(const LeafEntry& other) const {
        return hash < other.hash;
    }
};

// Merkle���ڵ�
struct MerkleNode {
    std::vector<uint8_t> hash;
    std::shared_ptr<MerkleNode> left;
    std::shared_ptr<MerkleNode> right;
    bool is_leaf;
    int index; // Ҷ�ӽڵ�������������е�����

    MerkleNode() : is_leaf(false), index(-1) {}

    // ����Ҷ�ӽڵ�
    static std::shared_ptr<MerkleNode> create_leaf(const LeafEntry& entry, int idx) {
        auto node = std::make_shared<MerkleNode>();
        node->hash = entry.hash;
        node->is_leaf = true;
        node->index = idx;
        return node;
    }

    // �����ڲ��ڵ� - RFC6962��׼
    static std::shared_ptr<MerkleNode> create_internal(
        std::shared_ptr<MerkleNode> left_child,
        std::shared_ptr<MerkleNode> right_child) {

        auto node = std::make_shared<MerkleNode>();
        node->left = left_child;
        node->right = right_child;
        node->is_leaf = false;

        // RFC6962: �ڲ��ڵ��ϣ = H(0x01 || left_hash || right_hash)
        std::vector<uint8_t> input;
        input.push_back(0x01);
        input.insert(input.end(), left_child->hash.begin(), left_child->hash.end());
        input.insert(input.end(), right_child->hash.begin(), right_child->hash.end());
        node->hash = SM3Hash::hash(input);

        return node;
    }
};

// ������֤���ṹ
struct InclusionProof {
    int leaf_index;                    // Ҷ�������е�����
    std::vector<uint8_t> leaf_hash;    // Ҷ�ӵĹ�ϣֵ
    std::vector<std::vector<uint8_t>> audit_path; // ���·��
    std::vector<bool> is_left_sibling; // ÿ��·���ڵ��Ƿ�Ϊ���ֵ�

    void print() const {
        std::cout << "������֤��:" << std::endl;
        std::cout << "  Ҷ������: " << leaf_index << std::endl;
        std::cout << "  Ҷ�ӹ�ϣ: " << SM3Hash::bytes_to_hex(leaf_hash) << std::endl;
        std::cout << "  ���·������: " << audit_path.size() << std::endl;
        for (size_t i = 0; i < audit_path.size(); i++) {
            std::cout << "    [" << i << "] " << (is_left_sibling[i] ? "��" : "��")
                << ": " << SM3Hash::bytes_to_hex(audit_path[i]) << std::endl;
        }
    }
};

// ��������֤���ṹ
struct NonInclusionProof {
    std::vector<uint8_t> target_hash;           // Ŀ���ϣ�������ڵģ�
    InclusionProof predecessor_proof;           // ǰ��Ҷ�ӵĴ�����֤��
    InclusionProof successor_proof;             // ���Ҷ�ӵĴ�����֤��
    bool has_predecessor;                       // �Ƿ���ǰ��
    bool has_successor;                         // �Ƿ��к��

    void print() const {
        std::cout << "��������֤��:" << std::endl;
        std::cout << "  Ŀ���ϣ: " << SM3Hash::bytes_to_hex(target_hash) << std::endl;
        std::cout << "  ��ǰ��: " << (has_predecessor ? "��" : "��") << std::endl;
        std::cout << "  �к��: " << (has_successor ? "��" : "��") << std::endl;

        if (has_predecessor) {
            std::cout << "  ǰ��֤��:" << std::endl;
            std::cout << "    ����: " << predecessor_proof.leaf_index << std::endl;
            std::cout << "    ��ϣ: " << SM3Hash::bytes_to_hex(predecessor_proof.leaf_hash) << std::endl;
        }

        if (has_successor) {
            std::cout << "  ���֤��:" << std::endl;
            std::cout << "    ����: " << successor_proof.leaf_index << std::endl;
            std::cout << "    ��ϣ: " << SM3Hash::bytes_to_hex(successor_proof.leaf_hash) << std::endl;
        }
    }
};

// Merkle������
class MerkleTree {
private:
    std::shared_ptr<MerkleNode> root;
    std::vector<LeafEntry> sorted_leaves;
    std::map<std::vector<uint8_t>, int> hash_to_index;
    int tree_size;

    // �洢ÿһ��Ľڵ��ϣ�����ڿ��ٲ���
    std::vector<std::vector<std::vector<uint8_t>>> level_hashes;

public:
    MerkleTree() : tree_size(0) {}

    // ����Merkle��
    void build_tree(std::vector<LeafEntry>& leaves) {
        if (leaves.empty()) {
            throw std::runtime_error("Ҷ���б���Ϊ��");
        }

        std::cout << "��ʼ����Merkle����Ҷ�ӽڵ�����: " << leaves.size() << std::endl;
        auto start_time = std::chrono::high_resolution_clock::now();

        // 1. ��Ҷ�Ӱ���ϣֵ����RFC6962Ҫ��
        std::sort(leaves.begin(), leaves.end());
        sorted_leaves = leaves;
        tree_size = static_cast<int>(leaves.size());

        // 2. ������ϣ��������ӳ��
        hash_to_index.clear();
        for (int i = 0; i < tree_size; i++) {
            hash_to_index[sorted_leaves[i].hash] = i;
        }

        // 3. Ԥ�������в�Ĺ�ϣֵ
        compute_all_level_hashes();

        // 4. ����Ҷ�ӽڵ�
        std::vector<std::shared_ptr<MerkleNode>> current_level;
        for (int i = 0; i < tree_size; i++) {
            current_level.push_back(MerkleNode::create_leaf(sorted_leaves[i], i));
        }

        // 5. �Ե����Ϲ�����
        while (current_level.size() > 1) {
            std::vector<std::shared_ptr<MerkleNode>> next_level;

            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    // �������ӽڵ�
                    auto parent = MerkleNode::create_internal(
                        current_level[i], current_level[i + 1]);
                    next_level.push_back(parent);
                }
                else {
                    // �������ڵ㣬���һ���ڵ����ϴ���
                    next_level.push_back(current_level[i]);
                }
            }

            current_level = next_level;
        }

        root = current_level[0];

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        std::cout << "Merkle���������" << std::endl;
        std::cout << "����ʱ��: " << duration.count() << " ����" << std::endl;
        std::cout << "����ϣ: " << SM3Hash::bytes_to_hex(root->hash) << std::endl;
    }

    // ��ȡ����ϣ
    std::vector<uint8_t> get_root_hash() const {
        if (!root) {
            throw std::runtime_error("����δ����");
        }
        return root->hash;
    }

    // ���ɴ�����֤��
    InclusionProof generate_inclusion_proof(const std::vector<uint8_t>& target_hash) {
        auto it = hash_to_index.find(target_hash);
        if (it == hash_to_index.end()) {
            throw std::runtime_error("Ŀ���ϣ������������");
        }

        int leaf_index = it->second;
        return generate_inclusion_proof_by_index(leaf_index);
    }

    // �����������ɴ�����֤�����޸��汾��
    InclusionProof generate_inclusion_proof_by_index(int leaf_index) {
        if (leaf_index < 0 || leaf_index >= tree_size) {
            throw std::runtime_error("Ҷ������������Χ");
        }

        InclusionProof proof;
        proof.leaf_index = leaf_index;
        proof.leaf_hash = sorted_leaves[leaf_index].hash;

        // ʹ��Ԥ����Ĳ㼶��ϣ������֤��
        int current_index = leaf_index;

        for (size_t level = 0; level < level_hashes.size() - 1; level++) {
            const auto& current_level_hashes = level_hashes[level];

            // ���������Ч��
            if (current_index < 0 || current_index >= static_cast<int>(current_level_hashes.size())) {
                break;
            }

            if (current_index % 2 == 0) {
                // ��ǰ�ڵ������ӽڵ�
                int sibling_index = current_index + 1;
                if (sibling_index < static_cast<int>(current_level_hashes.size())) {
                    proof.audit_path.push_back(current_level_hashes[sibling_index]);
                    proof.is_left_sibling.push_back(false); // �ֵ����ҽڵ�
                }
            }
            else {
                // ��ǰ�ڵ������ӽڵ�
                int sibling_index = current_index - 1;
                if (sibling_index >= 0) {
                    proof.audit_path.push_back(current_level_hashes[sibling_index]);
                    proof.is_left_sibling.push_back(true); // �ֵ�����ڵ�
                }
            }

            current_index = current_index / 2;
        }

        return proof;
    }

    // ���ɲ�������֤��
    NonInclusionProof generate_non_inclusion_proof(const std::vector<uint8_t>& target_hash) {
        NonInclusionProof proof;
        proof.target_hash = target_hash;

        // ���Ŀ���Ƿ���Ĳ�����
        if (hash_to_index.find(target_hash) != hash_to_index.end()) {
            throw std::runtime_error("Ŀ���ϣ�Ѵ��������У��޷����ɲ�������֤��");
        }

        // �������Ҷ���б����ҵ�ǰ���ͺ��
        int predecessor_idx = -1;
        int successor_idx = -1;

        for (int i = 0; i < tree_size; i++) {
            if (sorted_leaves[i].hash < target_hash) {
                predecessor_idx = i;
            }
            else {
                successor_idx = i;
                break;
            }
        }

        // ����ǰ���Ĵ�����֤��
        if (predecessor_idx >= 0) {
            proof.has_predecessor = true;
            proof.predecessor_proof = generate_inclusion_proof_by_index(predecessor_idx);
        }
        else {
            proof.has_predecessor = false;
        }

        // ���ɺ�̵Ĵ�����֤��
        if (successor_idx >= 0 && successor_idx < tree_size) {
            proof.has_successor = true;
            proof.successor_proof = generate_inclusion_proof_by_index(successor_idx);
        }
        else {
            proof.has_successor = false;
        }

        return proof;
    }

    // ��֤������֤��
    bool verify_inclusion_proof(const InclusionProof& proof, const std::vector<uint8_t>& root_hash) {
        if (proof.audit_path.size() != proof.is_left_sibling.size()) {
            return false;
        }

        std::vector<uint8_t> current_hash = proof.leaf_hash;

        for (size_t i = 0; i < proof.audit_path.size(); i++) {
            std::vector<uint8_t> input;
            input.push_back(0x01); // �ڲ��ڵ�ǰ׺

            if (proof.is_left_sibling[i]) {
                // �ֵ�����ڵ�
                input.insert(input.end(), proof.audit_path[i].begin(), proof.audit_path[i].end());
                input.insert(input.end(), current_hash.begin(), current_hash.end());
            }
            else {
                // �ֵ����ҽڵ�
                input.insert(input.end(), current_hash.begin(), current_hash.end());
                input.insert(input.end(), proof.audit_path[i].begin(), proof.audit_path[i].end());
            }

            current_hash = SM3Hash::hash(input);
        }

        return current_hash == root_hash;
    }

    // ��֤��������֤��
    bool verify_non_inclusion_proof(const NonInclusionProof& proof, const std::vector<uint8_t>& root_hash) {
        // 1. ��֤ǰ��֤����������ڣ�
        if (proof.has_predecessor) {
            if (!verify_inclusion_proof(proof.predecessor_proof, root_hash)) {
                return false;
            }
            // ���ǰ���Ĺ�ϣֵȷʵС��Ŀ���ϣ
            if (proof.predecessor_proof.leaf_hash >= proof.target_hash) {
                return false;
            }
        }

        // 2. ��֤���֤����������ڣ�
        if (proof.has_successor) {
            if (!verify_inclusion_proof(proof.successor_proof, root_hash)) {
                return false;
            }
            // ����̵Ĺ�ϣֵȷʵ����Ŀ���ϣ
            if (proof.successor_proof.leaf_hash <= proof.target_hash) {
                return false;
            }
        }

        // 3. ���ǰ���ͺ�̵�������
        if (proof.has_predecessor && proof.has_successor) {
            // ȷ��ǰ���ͺ����������
            if (proof.successor_proof.leaf_index != proof.predecessor_proof.leaf_index + 1) {
                return false;
            }
        }

        return true;
    }

    // ��ȡͳ����Ϣ
    void print_statistics() {
        if (!root) {
            std::cout << "����δ����" << std::endl;
            return;
        }

        int height = static_cast<int>(level_hashes.size());
        std::cout << "\n=== Merkle��ͳ����Ϣ ===" << std::endl;
        std::cout << "Ҷ�ӽڵ�����: " << tree_size << std::endl;
        std::cout << "���ĸ߶�: " << height << std::endl;
        std::cout << "����ϣ: " << SM3Hash::bytes_to_hex(root->hash) << std::endl;

        // ����֤������ͳ��
        if (tree_size > 0) {
            int avg_proof_length = 0;
            int test_count = std::min(100, tree_size);
            for (int i = 0; i < test_count; i++) {
                auto proof = generate_inclusion_proof_by_index(i);
                avg_proof_length += static_cast<int>(proof.audit_path.size());
            }
            avg_proof_length /= test_count;
            std::cout << "ƽ��֤������: " << avg_proof_length << " ����ϣֵ" << std::endl;
        }
    }

private:
    // Ԥ�������в�Ĺ�ϣֵ
    void compute_all_level_hashes() {
        level_hashes.clear();

        // ��0�㣺Ҷ�ӽڵ��ϣ
        std::vector<std::vector<uint8_t>> current_level;
        for (int i = 0; i < tree_size; i++) {
            current_level.push_back(sorted_leaves[i].hash);
        }
        level_hashes.push_back(current_level);

        // ������ϼ���
        while (current_level.size() > 1) {
            std::vector<std::vector<uint8_t>> next_level;

            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    // �������ӽڵ㣬���㸸�ڵ��ϣ
                    std::vector<uint8_t> input;
                    input.push_back(0x01);
                    input.insert(input.end(), current_level[i].begin(), current_level[i].end());
                    input.insert(input.end(), current_level[i + 1].begin(), current_level[i + 1].end());
                    next_level.push_back(SM3Hash::hash(input));
                }
                else {
                    // �������ڵ㣬���һ���ڵ����ϴ���
                    next_level.push_back(current_level[i]);
                }
            }

            level_hashes.push_back(next_level);
            current_level = next_level;
        }
    }
};

//����

class MerkleTreeDemo {
public:
    static void run_comprehensive_demo() {
        std::cout << "=== SM3 Merkle����RFC6962����ʾ���� ===" << std::endl;
        std::cout << "����10��Ҷ�ӽڵ��Merkle������ʾ֤����������֤\n" << std::endl;

        // ����С���ݼ�����
        std::cout << "1. С��ģ���ԣ�1000���ڵ㣩..." << std::endl;
        auto small_leaves = generate_test_leaves(1000);
        MerkleTree small_tree;
        small_tree.build_tree(small_leaves);
        test_basic_functionality(small_tree, small_leaves);

        // �ٽ��д��ģ����
        std::cout << "\n2. ���ģ���ԣ�10����ڵ㣩..." << std::endl;
        auto leaves = generate_test_leaves(100000);
        std::cout << "������ " << leaves.size() << " ��Ҷ�ӽڵ�" << std::endl;

        // ����Merkle��
        std::cout << "\n3. ����Merkle��..." << std::endl;
        MerkleTree tree;
        tree.build_tree(leaves);

        // ��ӡͳ����Ϣ
        tree.print_statistics();

        // ��ʾ������֤��
        std::cout << "\n4. ��ʾ������֤��..." << std::endl;
        demonstrate_inclusion_proofs(tree, leaves);

        // ��ʾ��������֤��
        std::cout << "\n5. ��ʾ��������֤��..." << std::endl;
        demonstrate_non_inclusion_proofs(tree);

        // ���ܲ���
        std::cout << "\n6. ���ܲ���..." << std::endl;
        performance_test(tree, leaves);
    }

private:
    static std::vector<LeafEntry> generate_test_leaves(int count) {
        std::vector<LeafEntry> leaves;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000000, 9999999);

        std::set<std::string> used_ids; // ȷ��Ψһ��

        for (int i = 0; i < count; i++) {
            std::string id;
            do {
                id = "user_" + std::to_string(dis(gen)) + "_data_" + std::to_string(i);
            } while (used_ids.count(id) > 0);

            used_ids.insert(id);
            leaves.emplace_back(id);

            if (count > 10000 && i > 0 && i % 10000 == 0) {
                std::cout << "  ������ " << i << " ��Ҷ�ӽڵ�..." << std::endl;
            }
        }

        return leaves;
    }

    static void test_basic_functionality(MerkleTree& tree, const std::vector<LeafEntry>& leaves) {
        auto root_hash = tree.get_root_hash();

        // ����ǰ����Ҷ�ӵĴ�����֤��
        for (int i = 0; i < std::min(5, static_cast<int>(leaves.size())); i++) {
            auto proof = tree.generate_inclusion_proof(leaves[i].hash);
            bool valid = tree.verify_inclusion_proof(proof, root_hash);
            std::cout << "����Ҷ�� " << i << " �Ĵ�����֤��: " << (valid ? "ͨ��" : "ʧ��") << std::endl;

            if (!valid) {
                std::cout << "����: �������ܲ���ʧ��!" << std::endl;
                return;
            }
        }

        std::cout << "�������ܲ���ͨ��!" << std::endl;
    }

    static void demonstrate_inclusion_proofs(MerkleTree& tree, const std::vector<LeafEntry>& leaves) {
        auto root_hash = tree.get_root_hash();

        // ���Լ������Ҷ�ӵĴ�����֤��
        std::vector<int> test_indices = { 0, 1000, 25000, 50000, 75000, 99999 };

        for (int idx : test_indices) {
            if (idx >= static_cast<int>(leaves.size())) continue;

            std::cout << "\n����Ҷ�� " << idx << ": \"" << leaves[idx].to_string() << "\"" << std::endl;

            try {
                // ����֤��
                auto start_time = std::chrono::high_resolution_clock::now();
                auto proof = tree.generate_inclusion_proof(leaves[idx].hash);
                auto end_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

                std::cout << "֤������ʱ��: " << duration.count() << " ΢��" << std::endl;
                std::cout << "֤������: " << proof.audit_path.size() << " ����ϣֵ" << std::endl;

                // ��֤֤��
                start_time = std::chrono::high_resolution_clock::now();
                bool valid = tree.verify_inclusion_proof(proof, root_hash);
                end_time = std::chrono::high_resolution_clock::now();
                duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

                std::cout << "֤����֤ʱ��: " << duration.count() << " ΢��" << std::endl;
                std::cout << "��֤���: " << (valid ? "��Ч" : "��Ч") << std::endl;

                if (!valid) {
                    std::cout << "����: ������֤����֤ʧ��!" << std::endl;
                }
            }
            catch (const std::exception& e) {
                std::cout << "���ɴ�����֤��ʱ����: " << e.what() << std::endl;
            }
        }
    }

    static void demonstrate_non_inclusion_proofs(MerkleTree& tree) {
        auto root_hash = tree.get_root_hash();

        // ����һЩ�����ڵ����ݽ��в���
        std::vector<std::string> non_existent_data = {
            "non_existent_user_1",
            "fake_data_12345",
            "missing_entry_999",
            "test_not_in_tree"
        };

        for (const auto& data : non_existent_data) {
            LeafEntry fake_entry(data);

            std::cout << "\n���Բ����ڵ�����: \"" << data << "\"" << std::endl;
            std::cout << "Ŀ���ϣ: " << SM3Hash::bytes_to_hex(fake_entry.hash) << std::endl;

            try {
                // ���ɲ�������֤��
                auto start_time = std::chrono::high_resolution_clock::now();
                auto proof = tree.generate_non_inclusion_proof(fake_entry.hash);
                auto end_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

                std::cout << "��������֤������ʱ��: " << duration.count() << " ΢��" << std::endl;

                // ��֤֤��
                start_time = std::chrono::high_resolution_clock::now();
                bool valid = tree.verify_non_inclusion_proof(proof, root_hash);
                end_time = std::chrono::high_resolution_clock::now();
                duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

                std::cout << "֤����֤ʱ��: " << duration.count() << " ΢��" << std::endl;
                std::cout << "��֤���: " << (valid ? "��Ч" : "��Ч") << std::endl;

                if (proof.has_predecessor) {
                    std::cout << "ǰ������: " << proof.predecessor_proof.leaf_index << std::endl;
                }
                if (proof.has_successor) {
                    std::cout << "�������: " << proof.successor_proof.leaf_index << std::endl;
                }

                if (!valid) {
                    std::cout << "����: ��������֤����֤ʧ��!" << std::endl;
                }

            }
            catch (const std::exception& e) {
                std::cout << "���ɲ�������֤��ʱ����: " << e.what() << std::endl;
            }
        }
    }

    static void performance_test(MerkleTree& tree, const std::vector<LeafEntry>& leaves) {
        const int test_count = 1000;
        auto root_hash = tree.get_root_hash();

        std::cout << "�� " << test_count << " �����Ҷ�ӽ������ܲ���..." << std::endl;

        // ���ѡ���������
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, static_cast<int>(leaves.size()) - 1);

        std::vector<int> test_indices;
        for (int i = 0; i < test_count; i++) {
            test_indices.push_back(dis(gen));
        }

        // ������֤�����ܲ���
        auto start_time = std::chrono::high_resolution_clock::now();

        int success_count = 0;
        for (int idx : test_indices) {
            try {
                auto proof = tree.generate_inclusion_proof(leaves[idx].hash);
                bool valid = tree.verify_inclusion_proof(proof, root_hash);
                if (valid) {
                    success_count++;
                }
                else {
                    std::cout << "��֤ʧ�ܣ�����: " << idx << std::endl;
                }
            }
            catch (const std::exception& e) {
                std::cout << "�������� " << idx << " ʱ����: " << e.what() << std::endl;
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        std::cout << "������֤�����Խ��:" << std::endl;
        std::cout << "  �ɹ���֤: " << success_count << "/" << test_count << std::endl;
        std::cout << "  ��ʱ��: " << duration.count() << " ����" << std::endl;
        if (success_count > 0) {
            std::cout << "  ƽ��ÿ��֤��: " << static_cast<double>(duration.count()) / success_count << " ����" << std::endl;
            std::cout << "  ÿ��ɴ���: " << static_cast<int>(success_count * 1000.0 / duration.count()) << " ��֤��" << std::endl;
        }
    }
};


int main() {
    try {
        MerkleTreeDemo::run_comprehensive_demo();
    }
    catch (const std::exception& e) {
        std::cerr << "����ִ�г���: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
