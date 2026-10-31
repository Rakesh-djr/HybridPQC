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

target_link_libraries(server_auth_phase4_6_fixed
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)

add_executable(client_auth_phase4_6_fixed
    src/client_auth_phase4_6_fixed.c
)

target_link_libraries(client_auth_phase4_6_fixed
    protocol_auth
    oqs
    OpenSSL::Crypto
    ws2_32
)