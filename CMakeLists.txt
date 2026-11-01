cmake_minimum_required(VERSION 3.20)

project(HybridPQC C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ============================================================
# OpenSSL
# ============================================================

set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")

find_package(OpenSSL REQUIRED)

message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto library: ${OPENSSL_CRYPTO_LIBRARY}")

# ============================================================
# liboqs
# ============================================================

set(LIBOQS_ROOT "C:/liboqs")

include_directories(
    ${LIBOQS_ROOT}/build/include
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

link_directories(
    ${LIBOQS_ROOT}/build/lib/Release
)

# ============================================================
# Common protocol
# ============================================================

add_library(protocol STATIC
    src/protocol.c
)

target_include_directories(protocol PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ============================================================
# ML-KEM test
# ============================================================

add_executable(mlkem_test
    src/mlkem_test.c
)

target_link_libraries(mlkem_test
    oqs
)

# ============================================================
# X25519 test
# ============================================================

add_executable(x25519_test
    src/x25519_test.c
)

target_link_libraries(x25519_test
    OpenSSL::Crypto
)

# ============================================================
# Hybrid test
# ============================================================

add_executable(hybrid_test
    src/hybrid_test.c
)

target_link_libraries(hybrid_test
    oqs
    OpenSSL::Crypto
)

# ============================================================
# AES-GCM test
# ============================================================

add_executable(aes_gcm_test
    src/aes_gcm_test.c
)

target_link_libraries(aes_gcm_test
    OpenSSL::Crypto
)

# ============================================================
# Integrated hybrid secure channel test
# ============================================================

add_executable(hybrid_secure_channel
    src/hybrid_secure_channel.c
)

target_link_libraries(hybrid_secure_channel
    oqs
    OpenSSL::Crypto
)

# ============================================================
# PQ Digital Signature test
# ============================================================

add_executable(signature_test
    src/signature_test.c
)

target_link_libraries(signature_test
    oqs
)
# ============================================================
# ML-DSA identity generator
# ============================================================

add_executable(generate_identity
    src/generate_identity.c
)

target_link_libraries(generate_identity
    oqs
)

# ============================================================
# SERVER
# ============================================================

add_executable(server
    src/server.c
)

target_link_libraries(server
    protocol
    oqs
    OpenSSL::Crypto
    ws2_32
)

# ============================================================
# CLIENT
# ============================================================

add_executable(client
    src/client.c
)

target_link_libraries(client
    protocol
    oqs
    OpenSSL::Crypto
    ws2_32
)
# ============================================================
# Authenticated Hybrid PQC Protocol
# ============================================================

add_library(protocol_auth STATIC
    src/protocol_auth.c
)

target_include_directories(protocol_auth PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ============================================================
# Authenticated Hybrid PQC Server
# ============================================================

add_executable(server_auth
    src/server_auth.c
)

target_link_libraries(server_auth
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)

# ============================================================
# Authenticated Hybrid PQC Client
# ============================================================

add_executable(client_auth
    src/client_auth.c
)

target_link_libraries(client_auth
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)
# ============================================================
# Phase 4.1 - Transcript Tampering Security Test
# ============================================================

add_executable(client_auth_phase4
    src/client_auth_phase4.c
)

target_link_libraries(client_auth_phase4
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)

# ============================================================
# Fake Bob ML-DSA-65 Identity Generator
# ============================================================

add_executable(generate_fake_identity
    src/generate_fake_identity.c
)

target_link_libraries(generate_fake_identity
    oqs
)
# ============================================================
# Phase 4.2 - Wrong Bob Public Key Security Test
# ============================================================

add_executable(client_auth_phase4_2
    src/client_auth_phase4_2.c
)

target_link_libraries(client_auth_phase4_2
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)
# ============================================================
# Phase 4.3 - ML-KEM Ciphertext Tampering Security Test
# ============================================================

add_executable(client_auth_phase4_3
    src/client_auth_phase4_3.c
)

target_link_libraries(client_auth_phase4_3
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)
# ============================================================
# Phase 4.4 - X25519 Public-Key Tampering Security Test
# ============================================================

add_executable(client_auth_phase4_4
    src/client_auth_phase4_4.c
)

target_link_libraries(client_auth_phase4_4
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)
# ============================================================
# Phase 4.5 - AES-256-GCM Ciphertext Tampering Security Test
# ============================================================

add_executable(client_auth_phase4_5
    src/client_auth_phase4_5.c
)

target_link_libraries(client_auth_phase4_5
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)
add_executable(server_auth_phase4_6
    src/server_auth_phase4_6.c
)

target_link_libraries(server_auth_phase4_6
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)

add_executable(client_auth_phase4_6
    src/client_auth_phase4_6.c
)

target_link_libraries(client_auth_phase4_6
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)
add_executable(server_auth_phase4_6_fixed
    src/server_auth_phase4_6_fixed.c
)

target_compile_definitions(server_auth_phase4_6_fixed
    PRIVATE PHASE6_CRYPTO_AGILITY
)

target_link_libraries(server_auth_phase4_6_fixed
    protocol_auth_phase6_768
    oqs
    OpenSSL::Crypto
    ws2_32
    Psapi
)

# Benchmark-only server variant that moves OpenSSL first-use initialization
# outside the timed handshake interval.
add_executable(server_auth_phase4_6_warmup
    src/server_auth_phase4_6_fixed.c
)

target_compile_definitions(server_auth_phase4_6_warmup
    PRIVATE PHASE5_PREWARM_CRYPTO PHASE6_CRYPTO_AGILITY
)

target_link_libraries(server_auth_phase4_6_warmup
    protocol_auth_phase6_768
    oqs
    OpenSSL::Crypto
    ws2_32
    Psapi
)

add_executable(client_auth_phase4_6_fixed
    src/client_auth_phase4_6_fixed.c
)

target_compile_definitions(client_auth_phase4_6_fixed
    PRIVATE PHASE6_CRYPTO_AGILITY
)

target_link_libraries(client_auth_phase4_6_fixed
    protocol_auth_phase6_768
    oqs
    OpenSSL::Crypto
    ws2_32
    Psapi
)

# ============================================================
# Phase 5 - Cryptographic Primitive Benchmarks
# ============================================================

add_executable(primitive_benchmark
    src/primitive_benchmark.c
)

target_link_libraries(primitive_benchmark
    oqs
    OpenSSL::Crypto
)

# Phase 6 policy prototype: selects among measured profiles under constraints.
add_library(phase6_crypto_policy STATIC
    src/crypto_policy.c
)
add_executable(phase6_policy_demo
    src/phase6_policy_demo.c
)
target_link_libraries(phase6_policy_demo phase6_crypto_policy)

# Runtime profile selection with a server that supports all three ML-KEM sets.
add_library(protocol_auth_phase6_adaptive STATIC
    src/protocol_auth.c
)
target_compile_definitions(protocol_auth_phase6_adaptive
    PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_ADAPTIVE
)

add_executable(client_auth_phase6_adaptive
    src/client_auth_phase4_6_fixed.c
)
target_compile_definitions(client_auth_phase6_adaptive
    PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_ADAPTIVE
)
target_link_libraries(client_auth_phase6_adaptive
    protocol_auth_phase6_adaptive oqs OpenSSL::Crypto ws2_32 Psapi
    phase6_crypto_policy
)

add_executable(server_auth_phase6_adaptive
    src/server_auth_phase4_6_fixed.c
)
target_compile_definitions(server_auth_phase6_adaptive
    PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_ADAPTIVE
)
target_link_libraries(server_auth_phase6_adaptive
    protocol_auth_phase6_adaptive oqs OpenSSL::Crypto ws2_32 Psapi
)

# Backend for Phase 7 experiments; the client connects to the impairment proxy
# on port 5555, while the proxy forwards to this server on port 5556.
add_executable(server_auth_phase7_backend
    src/server_auth_phase4_6_fixed.c
)
target_compile_definitions(server_auth_phase7_backend
    PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_ADAPTIVE SERVER_PORT=5556
)
target_link_libraries(server_auth_phase7_backend
    protocol_auth_phase6_adaptive oqs OpenSSL::Crypto ws2_32 Psapi
)

# Phase 8 simulator-only handshake. It uses a fixed public fixture through the
# provider API and a separate port; it does not represent a real QKD system.
add_executable(client_auth_phase8_qkd
    src/client_auth_phase4_6_fixed.c
    src/qkd_key_provider.c
)
target_compile_definitions(client_auth_phase8_qkd
    PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_ADAPTIVE
            PHASE8_QKD_SIMULATOR SERVER_PORT=5557
)
target_link_libraries(client_auth_phase8_qkd
    protocol_auth_phase6_adaptive oqs OpenSSL::Crypto ws2_32 Psapi
    phase6_crypto_policy
)

add_executable(server_auth_phase8_qkd
    src/server_auth_phase4_6_fixed.c
    src/qkd_key_provider.c
)
target_compile_definitions(server_auth_phase8_qkd
    PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_ADAPTIVE
            PHASE8_QKD_SIMULATOR SERVER_PORT=5557
)
target_link_libraries(server_auth_phase8_qkd
    protocol_auth_phase6_adaptive oqs OpenSSL::Crypto ws2_32 Psapi
)

# Phase 6 paired handshake builds. Client and server must use the same profile.
foreach(profile IN ITEMS 512 768 1024)
    add_library(protocol_auth_phase6_${profile} STATIC
        src/protocol_auth.c
    )
    target_compile_definitions(protocol_auth_phase6_${profile}
        PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_${profile}
    )

    add_executable(client_auth_phase6_${profile}
        src/client_auth_phase4_6_fixed.c
    )
    target_compile_definitions(client_auth_phase6_${profile}
        PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_${profile}
    )
    target_link_libraries(client_auth_phase6_${profile}
        protocol_auth_phase6_${profile} oqs OpenSSL::Crypto ws2_32 Psapi
    )

    add_executable(server_auth_phase6_${profile}
        src/server_auth_phase4_6_fixed.c
    )
    target_compile_definitions(server_auth_phase6_${profile}
        PRIVATE PHASE6_CRYPTO_AGILITY PHASE6_KEM_${profile}
    )
    target_link_libraries(server_auth_phase6_${profile}
        protocol_auth_phase6_${profile} oqs OpenSSL::Crypto ws2_32 Psapi
    )
endforeach()

# Phase 8 QKD abstraction demo. The provider is a fixed fixture that exercises
# key-source integration and hybrid HKDF composition; it is not real QKD.
add_executable(phase8_qkd_demo
    src/phase8_qkd_demo.c
    src/qkd_key_provider.c
)
target_link_libraries(phase8_qkd_demo OpenSSL::Crypto)
