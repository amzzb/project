pragma circom 2.0.0;

// Poseidon2 哈希函数的零知识证明实现
// 基于论文 "Poseidon2: A Faster Version of the Poseidon Hash Function"
// 参数: (n=256, t=2, d=5) RF=8, RP=56 或 (n=256, t=3, d=5) RF=8, RP=56

// S盒: x^5 mod p
template SBox() {
    signal input in;
    signal output out;
    
    signal x2, x4;
    x2 <== in * in;
    x4 <== x2 * x2;
    out <== x4 * in;
}

// 为所有元素添加轮常数 (用于外部轮)
template AddRoundConstants(t) {
    signal input in[t];
    signal input constants[t];
    signal output out[t];
    
    for (var i = 0; i < t; i++) {
        out[i] <== in[i] + constants[i];
    }
}

// 添加单个轮常数 (用于内部轮 - 只对第一个元素)
template AddSingleRoundConstant(t) {
    signal input in[t];
    signal input constant;
    signal output out[t];
    
    out[0] <== in[0] + constant;
    for (var i = 1; i < t; i++) {
        out[i] <== in[i];
    }
}

// MDS 线性层，适用于 t=2
// 矩阵: [[μ0, 1], [1, μ1]]，其中 μ0=2, μ1=3 (满足 MDS 条件)
template LinearLayerMDS2() {
    signal input in[2];
    signal output out[2];
    
    // 使用 μ0=2, μ1=3，满足 μ0*μ1 - 1 = 6 - 1 = 5 ≠ 0
    // 矩阵乘法:
    // out[0] = 2*in[0] + 1*in[1]
    // out[1] = 1*in[0] + 3*in[1]
    
    out[0] <== 2 * in[0] + in[1];
    out[1] <== in[0] + 3 * in[1];
}

// MDS 线性层，适用于 t=3
// 矩阵: [[μ0, 1, 1], [1, μ1, 1], [1, 1, μ2]]，其中 μ0=2, μ1=3, μ2=5
template LinearLayerMDS3() {
    signal input in[3];
    signal output out[3];
    
    // 使用 μ0=2, μ1=3, μ2=5，满足 MDS 条件
    // 矩阵乘法:
    // out[0] = 2*in[0] + 1*in[1] + 1*in[2]
    // out[1] = 1*in[0] + 3*in[1] + 1*in[2] 
    // out[2] = 1*in[0] + 1*in[1] + 5*in[2]
    
    out[0] <== 2 * in[0] + in[1] + in[2];
    out[1] <== in[0] + 3 * in[1] + in[2];
    out[2] <== in[0] + in[1] + 5 * in[2];
}

// 外部轮 (完整轮)，适用于 t=2
template ExternalRound2() {
    signal input in[2];
    signal input constants[2];
    signal output out[2];
    
    component addConstants = AddRoundConstants(2);
    component sbox[2];
    component linearLayer = LinearLayerMDS2();
    
    // 添加轮常数
    for (var i = 0; i < 2; i++) {
        addConstants.in[i] <== in[i];
        addConstants.constants[i] <== constants[i];
    }
    
    // 对所有元素应用 S盒
    for (var i = 0; i < 2; i++) {
        sbox[i] = SBox();
        sbox[i].in <== addConstants.out[i];
    }
    
    // 应用线性层
    linearLayer.in[0] <== sbox[0].out;
    linearLayer.in[1] <== sbox[1].out;
    
    out[0] <== linearLayer.out[0];
    out[1] <== linearLayer.out[1];
}

// 外部轮 (完整轮)，适用于 t=3
template ExternalRound3() {
    signal input in[3];
    signal input constants[3];
    signal output out[3];
    
    component addConstants = AddRoundConstants(3);
    component sbox[3];
    component linearLayer = LinearLayerMDS3();
    
    // 添加轮常数
    for (var i = 0; i < 3; i++) {
        addConstants.in[i] <== in[i];
        addConstants.constants[i] <== constants[i];
    }
    
    // 对所有元素应用 S盒
    for (var i = 0; i < 3; i++) {
        sbox[i] = SBox();
        sbox[i].in <== addConstants.out[i];
    }
    
    // 应用线性层
    linearLayer.in[0] <== sbox[0].out;
    linearLayer.in[1] <== sbox[1].out;
    linearLayer.in[2] <== sbox[2].out;
    
    out[0] <== linearLayer.out[0];
    out[1] <== linearLayer.out[1];
    out[2] <== linearLayer.out[2];
}

// 内部轮 (部分轮)，适用于 t=2
template InternalRound2() {
    signal input in[2];
    signal input constant;
    signal output out[2];
    
    component addConstant = AddSingleRoundConstant(2);
    component sbox = SBox();
    component linearLayer = LinearLayerMDS2();
    
    // 只对第一个元素添加轮常数
    addConstant.in[0] <== in[0];
    addConstant.in[1] <== in[1];
    addConstant.constant <== constant;
    
    // 只对第一个元素应用 S盒
    sbox.in <== addConstant.out[0];
    
    // 应用线性层
    linearLayer.in[0] <== sbox.out;
    linearLayer.in[1] <== addConstant.out[1];
    
    out[0] <== linearLayer.out[0];
    out[1] <== linearLayer.out[1];
}

// 内部轮 (部分轮)，适用于 t=3
template InternalRound3() {
    signal input in[3];
    signal input constant;
    signal output out[3];
    
    component addConstant = AddSingleRoundConstant(3);
    component sbox = SBox();
    component linearLayer = LinearLayerMDS3();
    
    // 只对第一个元素添加轮常数
    addConstant.in[0] <== in[0];
    addConstant.in[1] <== in[1];
    addConstant.in[2] <== in[2];
    addConstant.constant <== constant;
    
    // 只对第一个元素应用 S盒
    sbox.in <== addConstant.out[0];
    
    // 应用线性层
    linearLayer.in[0] <== sbox.out;
    linearLayer.in[1] <== addConstant.out[1];
    linearLayer.in[2] <== addConstant.out[2];
    
    out[0] <== linearLayer.out[0];
    out[1] <== linearLayer.out[1];
    out[2] <== linearLayer.out[2];
}

// Poseidon2 置换函数，适用于 t=2 (RF=8, RP=56)
template Poseidon2Perm2() {
    signal input in[2];
    signal output out[2];
    
    // 轮常数 (这些需要根据 Poseidon2 规范生成)
    // 为了演示，使用占位符数值 - 需要替换为实际常数
    var external_constants[8][2] = [
        [0x01, 0x02], [0x03, 0x04], [0x05, 0x06], [0x07, 0x08],
        [0x09, 0x0a], [0x0b, 0x0c], [0x0d, 0x0e], [0x0f, 0x10]
    ];
    
    var internal_constants[56] = [
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48
    ];
    
    component initialLinear = LinearLayerMDS2();
    component externalRounds[8];
    component internalRounds[56];
    
    signal states[65][2];
    
    // 初始线性层 (相对于 Poseidon 的关键区别)
    initialLinear.in[0] <== in[0];
    initialLinear.in[1] <== in[1];
    states[0][0] <== initialLinear.out[0];
    states[0][1] <== initialLinear.out[1];
    
    // 前 4 个外部轮 (RF/2 = 4)
    for (var i = 0; i < 4; i++) {
        externalRounds[i] = ExternalRound2();
        externalRounds[i].in[0] <== states[i][0];
        externalRounds[i].in[1] <== states[i][1];
        externalRounds[i].constants[0] <== external_constants[i][0];
        externalRounds[i].constants[1] <== external_constants[i][1];
        states[i + 1][0] <== externalRounds[i].out[0];
        states[i + 1][1] <== externalRounds[i].out[1];
    }
    
    // 56 个内部轮 (RP = 56)
    for (var i = 0; i < 56; i++) {
        internalRounds[i] = InternalRound2();
        internalRounds[i].in[0] <== states[i + 4][0];
        internalRounds[i].in[1] <== states[i + 4][1];
        internalRounds[i].constant <== internal_constants[i];
        states[i + 5][0] <== internalRounds[i].out[0];
        states[i + 5][1] <== internalRounds[i].out[1];
    }
    
    // 后 4 个外部轮
    for (var i = 0; i < 4; i++) {
        externalRounds[i + 4] = ExternalRound2();
        externalRounds[i + 4].in[0] <== states[i + 60][0];
        externalRounds[i + 4].in[1] <== states[i + 60][1];
        externalRounds[i + 4].constants[0] <== external_constants[i + 4][0];
        externalRounds[i + 4].constants[1] <== external_constants[i + 4][1];
        states[i + 61][0] <== externalRounds[i + 4].out[0];
        states[i + 61][1] <== externalRounds[i + 4].out[1];
    }
    
    out[0] <== states[64][0];
    out[1] <== states[64][1];
}

// Poseidon2 置换函数，适用于 t=3 (RF=8, RP=56)
template Poseidon2Perm3() {
    signal input in[3];
    signal output out[3];
    
    // 轮常数 (占位符 - 需要替换为实际的 Poseidon2 常数)
    var external_constants[8][3] = [
        [0x01, 0x02, 0x03], [0x04, 0x05, 0x06], [0x07, 0x08, 0x09], [0x0a, 0x0b, 0x0c],
        [0x0d, 0x0e, 0x0f], [0x10, 0x11, 0x12], [0x13, 0x14, 0x15], [0x16, 0x17, 0x18]
    ];
    
    var internal_constants[56] = [
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50
    ];
    
    component initialLinear = LinearLayerMDS3();
    component externalRounds[8];
    component internalRounds[56];
    
    signal states[65][3];
    
    // 初始线性层
    initialLinear.in[0] <== in[0];
    initialLinear.in[1] <== in[1];
    initialLinear.in[2] <== in[2];
    states[0][0] <== initialLinear.out[0];
    states[0][1] <== initialLinear.out[1];
    states[0][2] <== initialLinear.out[2];
    
    // 前 4 个外部轮
    for (var i = 0; i < 4; i++) {
        externalRounds[i] = ExternalRound3();
        externalRounds[i].in[0] <== states[i][0];
        externalRounds[i].in[1] <== states[i][1];
        externalRounds[i].in[2] <== states[i][2];
        externalRounds[i].constants[0] <== external_constants[i][0];
        externalRounds[i].constants[1] <== external_constants[i][1];
        externalRounds[i].constants[2] <== external_constants[i][2];
        states[i + 1][0] <== externalRounds[i].out[0];
        states[i + 1][1] <== externalRounds[i].out[1];
        states[i + 1][2] <== externalRounds[i].out[2];
    }
    
    // 56 个内部轮
    for (var i = 0; i < 56; i++) {
        internalRounds[i] = InternalRound3();
        internalRounds[i].in[0] <== states[i + 4][0];
        internalRounds[i].in[1] <== states[i + 4][1];
        internalRounds[i].in[2] <== states[i + 4][2];
        internalRounds[i].constant <== internal_constants[i];
        states[i + 5][0] <== internalRounds[i].out[0];
        states[i + 5][1] <== internalRounds[i].out[1];
        states[i + 5][2] <== internalRounds[i].out[2];
    }
    
    // 后 4 个外部轮
    for (var i = 0; i < 4; i++) {
        externalRounds[i + 4] = ExternalRound3();
        externalRounds[i + 4].in[0] <== states[i + 60][0];
        externalRounds[i + 4].in[1] <== states[i + 60][1];
        externalRounds[i + 4].in[2] <== states[i + 60][2];
        externalRounds[i + 4].constants[0] <== external_constants[i + 4][0];
        externalRounds[i + 4].constants[1] <== external_constants[i + 4][1];
        externalRounds[i + 4].constants[2] <== external_constants[i + 4][2];
        states[i + 61][0] <== externalRounds[i + 4].out[0];
        states[i + 61][1] <== externalRounds[i + 4].out[1];
        states[i + 61][2] <== externalRounds[i + 4].out[2];
    }
    
    out[0] <== states[64][0];
    out[1] <== states[64][1];
    out[2] <== states[64][2];
}

// Poseidon2 哈希函数，适用于单个块输入 (t=2)
template Poseidon2Hash2() {
    signal input in[2];
    signal output hash;
    
    component perm = Poseidon2Perm2();
    perm.in[0] <== in[0];
    perm.in[1] <== in[1];
    
    // 输出第一个元素作为哈希 (海绵构造)
    hash <== perm.out[0];
}

// Poseidon2 哈希函数，适用于单个块输入 (t=3)
template Poseidon2Hash3() {
    signal input in[2];  // 只有 2 个输入，第三个是容量 (设为 0)
    signal output hash;
    
    component perm = Poseidon2Perm3();
    perm.in[0] <== in[0];
    perm.in[1] <== in[1];
    perm.in[2] <== 0;    // 容量元素设为 0
    
    // 输出第一个元素作为哈希
    hash <== perm.out[0];
}

// 哈希原象零知识证明的主电路
// 公开输入: 哈希值
// 私有输入: 原象
template Poseidon2PreimageProof() {
    // 私有输入 (原象)
    signal private input preimage[2];
    
    // 公开输入 (哈希值)
    signal input hash;
    
    // 计算原象的哈希
    component hasher = Poseidon2Hash2();
    hasher.in[0] <== preimage[0];
    hasher.in[1] <== preimage[1];
    
    // 约束: 计算出的哈希必须等于公开哈希
    hash === hasher.hash;
}

// 使用 t=3 的替代版本
template Poseidon2PreimageProofT3() {
    // 私有输入 (原象)
    signal private input preimage[2];
    
    // 公开输入 (哈希值)
    signal input hash;
    
    // 计算原象的哈希
    component hasher = Poseidon2Hash3();
    hasher.in[0] <== preimage[0];
    hasher.in[1] <== preimage[1];
    
    // 约束: 计算出的哈希必须等于公开哈希
    hash === hasher.hash;
}

// 主电路 - 修改这里在 t=2 和 t=3 版本之间切换
component main = Poseidon2PreimageProof();