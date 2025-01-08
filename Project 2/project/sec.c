#include <stdint.h>
#include <stdlib.h>
#include<string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

// current state for handshake
int state_sec = 0;              
uint8_t nonce[NONCE_SIZE];      // store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // peer's nonce to sign

void init_sec(int initial_state) {
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        generate_private_key();
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
        // initializing client hello
    } else if(state_sec == SERVER_CLIENT_HELLO_AWAIT){
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    }
    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch(state_sec){
        case CLIENT_CLIENT_HELLO_SEND: {
            print("SEND CLIENT HELLO");

            // construct Client Hello message
            size_t total_length = 1 + 2 + 1 + 2 + NONCE_SIZE;

            if(max_length < total_length)
                return -1; // not enough buffer space

            uint8_t* ptr = buf;

            *ptr++ = CLIENT_HELLO; // type

            uint16_t length = 1 + 2 + NONCE_SIZE;
            uint16_t net_length = htons(length);
            memcpy(ptr, &net_length, 2);
            ptr +=2;

            *ptr++ = NONCE_CLIENT_HELLO; // nested TLV

            uint16_t nonce_length = htons(NONCE_SIZE);
            memcpy(ptr, &nonce_length, 2);
            ptr +=2;

            memcpy(ptr, nonce, NONCE_SIZE);
            ptr += NONCE_SIZE;

            state_sec = CLIENT_SERVER_HELLO_AWAIT;
            return ptr - buf;
        }
        case SERVER_SERVER_HELLO_SEND: {
            print("SEND SERVER HELLO");

            uint8_t signature[255];
            size_t sig_size = sign(peer_nonce, NONCE_SIZE, signature); // signing nonce

            size_t nonce_tlv_length = 1 + 2 + NONCE_SIZE;
            size_t cert_tlv_length = cert_size;
            size_t sig_tlv_length = 1 + 2 + sig_size;

            size_t total_length = nonce_tlv_length + cert_tlv_length + sig_tlv_length;
            size_t message_length = 1 + 2 + total_length;

            if(max_length < message_length)
                return -1;

            uint8_t* ptr = buf;

            *ptr++ = SERVER_HELLO; // type

            uint16_t net_total_length = htons(total_length);
            memcpy(ptr, &net_total_length, 2);
            ptr +=2;

            // nonce TLV
            *ptr++ = NONCE_SERVER_HELLO;
            uint16_t net_nonce_length = htons(NONCE_SIZE);
            memcpy(ptr, &net_nonce_length, 2);
            ptr +=2;
            memcpy(ptr, nonce, NONCE_SIZE);
            ptr += NONCE_SIZE;

            // certificate TLV
            memcpy(ptr, certificate, cert_size);
            ptr += cert_size;

            // signature TLV
            *ptr++ = NONCE_SIGNATURE_SERVER_HELLO;
            uint16_t net_sig_length = htons(sig_size);
            memcpy(ptr, &net_sig_length, 2);
            ptr +=2;
            memcpy(ptr, signature, sig_size);
            ptr += sig_size;

            state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
            return ptr - buf;
        }
        case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
            print("SEND KEY EXCHANGE REQUEST");

            uint8_t signature[255];
            size_t sig_size = sign(peer_nonce, NONCE_SIZE, signature);

            size_t cert_tlv_length = cert_size;
            size_t sig_tlv_length = 1 + 2 + sig_size;
            size_t total_length = cert_tlv_length + sig_tlv_length;
            size_t message_length = 1 + 2 + total_length;

            if(max_length < message_length)
                return -1;

            uint8_t* ptr = buf;

            *ptr++ = KEY_EXCHANGE_REQUEST; // type

            uint16_t net_total_length = htons(total_length);
            memcpy(ptr, &net_total_length, 2);
            ptr +=2;

            memcpy(ptr, certificate, cert_size); // certificate
            ptr += cert_size;

            *ptr++ = NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST;
            uint16_t net_sig_length = htons(sig_size);
            memcpy(ptr, &net_sig_length, 2);
            ptr +=2;
            memcpy(ptr, signature, sig_size);
            ptr += sig_size;

            derive_secret();
            derive_keys();

            state_sec = CLIENT_FINISHED_AWAIT;
            return ptr - buf;
        }
        case SERVER_FINISHED_SEND: {
            print("SEND FINISHED");

            if(max_length < 1 + 2)
                return -1;

            uint8_t* ptr = buf;
            *ptr++ = FINISHED;
            uint16_t length = 0;
            uint16_t net_length = htons(length);
            memcpy(ptr, &net_length, 2);
            ptr +=2;

            state_sec = DATA_STATE;
            return ptr - buf;
        }
        case DATA_STATE: {
            // reading data
            uint8_t plaintext[943];
            ssize_t stdin_size = input_io(plaintext, sizeof(plaintext));

            if(stdin_size <=0)
                return 0; // nothing to send

            uint8_t iv[IV_SIZE];
            uint8_t ciphertext[960];
            size_t ciphertext_size = encrypt_data(plaintext, stdin_size, iv, ciphertext);

            uint8_t hmac_input[IV_SIZE + ciphertext_size];
            memcpy(hmac_input, iv, IV_SIZE);
            memcpy(hmac_input + IV_SIZE, ciphertext, ciphertext_size);

            uint8_t mac_code[MAC_SIZE];
            hmac(hmac_input, IV_SIZE + ciphertext_size, mac_code);

            size_t iv_tlv_length = 1 + 2 + IV_SIZE;
            size_t cipher_tlv_length = 1 + 2 + ciphertext_size;
            size_t mac_tlv_length = 1 + 2 + MAC_SIZE;
            size_t total_length = iv_tlv_length + cipher_tlv_length + mac_tlv_length;
            size_t message_length = 1 + 2 + total_length;

            if(max_length < message_length)
                return -1;

            uint8_t* ptr = buf;

            *ptr++ = DATA; // type

            uint16_t net_total_length = htons(total_length);
            memcpy(ptr, &net_total_length, 2);
            ptr +=2;

            // IV TLV
            *ptr++ = INITIALIZATION_VECTOR;
            uint16_t net_iv_length = htons(IV_SIZE);
            memcpy(ptr, &net_iv_length, 2);
            ptr +=2;
            memcpy(ptr, iv, IV_SIZE);
            ptr += IV_SIZE;

            // Ciphertext TLV
            *ptr++ = CIPHERTEXT;
            uint16_t net_cipher_length = htons(ciphertext_size);
            memcpy(ptr, &net_cipher_length, 2);
            ptr +=2;
            memcpy(ptr, ciphertext, ciphertext_size);
            ptr += ciphertext_size;

            // MAC TLV
            *ptr++ = MESSAGE_AUTHENTICATION_CODE;
            uint16_t net_mac_length = htons(MAC_SIZE);
            memcpy(ptr, &net_mac_length, 2);
            ptr +=2;
            memcpy(ptr, mac_code, MAC_SIZE);
            ptr += MAC_SIZE;

            fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, ciphertext_size);
            return ptr - buf;
        }
        default:
            return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch(state_sec){
        case SERVER_CLIENT_HELLO_AWAIT: {
            if(length < 1 + 2)
                exit(4);
            uint8_t type = *buf;
            if(type != CLIENT_HELLO)
                exit(4);

            print("RECV CLIENT HELLO");

            uint16_t total_length = ntohs(*(uint16_t*)(buf +1));
            if(length < 1 + 2 + total_length)
                exit(4);

            uint8_t* ptr = buf +3;

            // parse nonce
            if(ptr +1 +2 + NONCE_SIZE > buf + length)
                exit(4);
            uint8_t nested_type = *ptr++;
            if(nested_type != NONCE_CLIENT_HELLO)
                exit(4);
            uint16_t nested_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(nested_length != NONCE_SIZE)
                exit(4);
            memcpy(peer_nonce, ptr, NONCE_SIZE);
            ptr += NONCE_SIZE;

            state_sec = SERVER_SERVER_HELLO_SEND;
            break;
        }
        case CLIENT_SERVER_HELLO_AWAIT: {
            if(length < 1 + 2)
                exit(4);
            uint8_t type = *buf;
            if(type != SERVER_HELLO)
                exit(4);

            print("RECV SERVER HELLO");

            uint16_t total_length = ntohs(*(uint16_t*)(buf +1));
            if(length < 1 + 2 + total_length)
                exit(4);

            uint8_t* ptr = buf +3;
            uint8_t* end = buf +3 + total_length;

            // parse server nonce
            if(ptr +1 +2 + NONCE_SIZE > end)
                exit(4);
            uint8_t nonce_type = *ptr++;
            if(nonce_type != NONCE_SERVER_HELLO)
                exit(4);
            uint16_t nonce_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(nonce_length != NONCE_SIZE)
                exit(4);
            memcpy(peer_nonce, ptr, NONCE_SIZE); // server's nonce
            ptr += NONCE_SIZE;

            // parse certificate
            if(ptr +1 +2 > end)
                exit(1);
            uint8_t cert_type = *ptr++;
            if(cert_type != CERTIFICATE)
                exit(1);
            uint16_t cert_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(ptr + cert_length > end)
                exit(4);
            uint8_t* cert_ptr = ptr;
            size_t cert_size_received = cert_length;

            // parse certificate inner TLVs
            uint8_t* cert_inner_ptr = ptr;
            ptr += cert_length;

            // parse public key
            if(cert_inner_ptr +1 +2 > ptr)
                exit(1);
            uint8_t pubkey_type = *cert_inner_ptr++;
            if(pubkey_type != PUBLIC_KEY)
                exit(1);
            uint16_t pubkey_length = ntohs(*(uint16_t*)cert_inner_ptr);
            cert_inner_ptr +=2;
            if(cert_inner_ptr + pubkey_length > ptr)
                exit(1);
            uint8_t* pubkey_data = cert_inner_ptr;
            size_t pubkey_size = pubkey_length;
            cert_inner_ptr += pubkey_length;

            // parse signature
            if(cert_inner_ptr +1 +2 > ptr)
                exit(1);
            uint8_t sig_type = *cert_inner_ptr++;
            if(sig_type != SIGNATURE)
                exit(1);
            uint16_t sig_length = ntohs(*(uint16_t*)cert_inner_ptr);
            cert_inner_ptr +=2;
            if(cert_inner_ptr + sig_length > ptr)
                exit(1);
            uint8_t* signature_data = cert_inner_ptr;
            size_t signature_size = sig_length;
            cert_inner_ptr += sig_length;

            load_peer_public_key(pubkey_data, pubkey_size);

            // verify certificate
            int result = verify(pubkey_data, pubkey_size, signature_data, signature_size, ec_ca_public_key);
            if(result !=1)
                exit(1);

            // parse signature of nonce
            if(ptr +1 +2 > end)
                exit(4);
            uint8_t sig_nonce_type = *ptr++;
            if(sig_nonce_type != NONCE_SIGNATURE_SERVER_HELLO)
                exit(4);
            uint16_t sig_nonce_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(ptr + sig_nonce_length > end)
                exit(4);
            uint8_t* sig_nonce_data = ptr;
            size_t sig_nonce_size = sig_nonce_length;
            ptr += sig_nonce_length;

            // verify signature
            result = verify(nonce, NONCE_SIZE, sig_nonce_data, sig_nonce_size, ec_peer_public_key);
            if(result !=1)
                exit(2);

            state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
            break;
        }
        case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
            if(length < 1 + 2)
                exit(4);
            uint8_t type = *buf;
            if(type != KEY_EXCHANGE_REQUEST)
                exit(4);

            print("RECV KEY EXCHANGE REQUEST");

            uint16_t total_length = ntohs(*(uint16_t*)(buf +1));
            if(length < 1 + 2 + total_length)
                exit(4);

            uint8_t* ptr = buf +3;
            uint8_t* end = buf +3 + total_length;

            // parse certificate
            if(ptr +1 +2 > end)
                exit(1);
            uint8_t cert_type = *ptr++;
            if(cert_type != CERTIFICATE)
                exit(1);
            uint16_t cert_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(ptr + cert_length > end)
                exit(1);
            uint8_t* cert_ptr = ptr;
            size_t cert_size_received = cert_length;

            // parse certificate inner TLVs
            uint8_t* cert_inner_ptr = ptr;
            ptr += cert_length;

            // parse public key
            if(cert_inner_ptr +1 +2 > ptr)
                exit(1);
            uint8_t pubkey_type = *cert_inner_ptr++;
            if(pubkey_type != PUBLIC_KEY)
                exit(1);
            uint16_t pubkey_length = ntohs(*(uint16_t*)cert_inner_ptr);
            cert_inner_ptr +=2;
            if(cert_inner_ptr + pubkey_length > ptr)
                exit(1);
            uint8_t* pubkey_data = cert_inner_ptr;
            size_t pubkey_size = pubkey_length;
            cert_inner_ptr += pubkey_length;

            // parse signature
            if(cert_inner_ptr +1 +2 > ptr)
                exit(1);
            uint8_t sig_type = *cert_inner_ptr++;
            if(sig_type != SIGNATURE)
                exit(1);
            uint16_t sig_length = ntohs(*(uint16_t*)cert_inner_ptr);
            cert_inner_ptr +=2;
            if(cert_inner_ptr + sig_length > ptr)
                exit(1);
            uint8_t* signature_data = cert_inner_ptr;
            size_t signature_size = sig_length;
            cert_inner_ptr += sig_length;

            load_peer_public_key(pubkey_data, pubkey_size);

            // verify self-signed certificate
            int result = verify(pubkey_data, pubkey_size, signature_data, signature_size, ec_peer_public_key);
            if(result !=1)
                exit(1);

            // parse signature of nonce
            if(ptr +1 +2 > end)
                exit(4);
            uint8_t sig_nonce_type = *ptr++;
            if(sig_nonce_type != NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST)
                exit(4);
            uint16_t sig_nonce_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(ptr + sig_nonce_length > end)
                exit(4);
            uint8_t* sig_nonce_data = ptr;
            size_t sig_nonce_size = sig_nonce_length;
            ptr += sig_nonce_length;

            // verify signature
            result = verify(nonce, NONCE_SIZE, sig_nonce_data, sig_nonce_size, ec_peer_public_key);
            if(result !=1)
                exit(2);

            derive_secret();
            derive_keys();

            state_sec = SERVER_FINISHED_SEND;
            break;
        }
        case CLIENT_FINISHED_AWAIT: {
            if(length < 1 + 2)
                exit(4);
            uint8_t type = *buf;
            if(type != FINISHED)
                exit(4);

            print("RECV FINISHED");

            state_sec = DATA_STATE;
            break;
        }
        case DATA_STATE: {
            if(length < 1 + 2)
                exit(4);
            uint8_t type = *buf;
            if(type != DATA)
                exit(4);

            print("RECV DATA");

            uint16_t total_length = ntohs(*(uint16_t*)(buf +1));
            if(length < 1 + 2 + total_length)
                exit(4);

            uint8_t* ptr = buf +3;
            uint8_t* end = buf +3 + total_length;

            // parse IV
            if(ptr +1 +2 + IV_SIZE > end)
                exit(4);
            uint8_t iv_type = *ptr++;
            if(iv_type != INITIALIZATION_VECTOR)
                exit(4);
            uint16_t iv_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(iv_length != IV_SIZE)
                exit(4);
            uint8_t iv[IV_SIZE];
            memcpy(iv, ptr, IV_SIZE);
            ptr += IV_SIZE;

            // parse ciphertext
            if(ptr +1 +2 > end)
                exit(4);
            uint8_t cipher_type = *ptr++;
            if(cipher_type != CIPHERTEXT)
                exit(4);
            uint16_t cipher_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(ptr + cipher_length > end)
                exit(4);
            uint8_t* ciphertext = ptr;
            size_t ciphertext_size = cipher_length;
            ptr += ciphertext_size;

            // parse MAC
            if(ptr +1 +2 + MAC_SIZE > end)
                exit(4);
            uint8_t mac_type = *ptr++;
            if(mac_type != MESSAGE_AUTHENTICATION_CODE)
                exit(4);
            uint16_t mac_length = ntohs(*(uint16_t*)ptr);
            ptr +=2;
            if(mac_length != MAC_SIZE)
                exit(4);
            uint8_t mac_code[MAC_SIZE];
            memcpy(mac_code, ptr, MAC_SIZE);
            ptr += MAC_SIZE;

            // verify HMAC
            uint8_t hmac_input[IV_SIZE + ciphertext_size];
            memcpy(hmac_input, iv, IV_SIZE);
            memcpy(hmac_input + IV_SIZE, ciphertext, ciphertext_size);

            uint8_t expected_mac[MAC_SIZE];
            hmac(hmac_input, IV_SIZE + ciphertext_size, expected_mac);

            if(memcmp(mac_code, expected_mac, MAC_SIZE) !=0)
                exit(3); // bad MAC

            // decrypt ciphertext
            uint8_t plaintext[1024];
            size_t plaintext_size = decrypt_cipher(ciphertext, ciphertext_size, iv, plaintext);

            output_io(plaintext, plaintext_size);

            fprintf(stderr, "RECV DATA PT %ld CT %lu\n", plaintext_size, ciphertext_size);
            break;
        }
        default:
            break;
    }
}
