#ifndef BITCOIN_RPC_COMMON_H
#define BITCOIN_RPC_COMMON_H
#include "../../secp256k1/include/secp256k1.h"

class SecPair
{
public:
    unsigned char m[32] = {0};
    unsigned char n[32] = {0};
    bool rand();
    bool operator==(const SecPair& other) const;
};

class RhoPoint : public SecPair
{
public:
    secp256k1_pubkey x;
    bool rand();
};

class RhoState : public RhoPoint
{
public:
    uint64_t times;
};

bool rho_F(secp256k1_context* ctx, RhoState& s);
void set_int256(unsigned char* cn, const char* n);
void set_int(unsigned char* cn, int64_t n);
void create(const secp256k1_context* ctx, secp256k1_pubkey* pk, const unsigned char* m, const unsigned char* n);
#endif // BITCOIN_RPC_COMMON_H
