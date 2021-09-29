#include <stdio.h>

typedef unsigned char           uint8_t;
typedef unsigned short          uint16_t;
typedef unsigned int            uint32_t;
typedef unsigned long long      uint64_t;

//#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-
//Total Functions
void S_layer_128(uint8_t In_text[]);
void P_layer_128(uint8_t In_text[]);
void Inv_S_layer_128(uint8_t In_text[]);
void Inv_P_layer_128(uint8_t In_text[]);
void Key_XOR_128_256(uint16_t In_text[], uint16_t Key[], uint16_t Round);
void PIPO_128_256_D_C(uint8_t Plaintext[], uint8_t Key[], uint8_t Ciphertext[]);
//#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-


//#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-
//Specific Implementations
void S_layer_128(uint16_t In_text[]){
    uint16_t *x = In_text; // Bit_slide pointer of Plaintext
    uint16_t T[3]; // Temporary value
    // S5_1
    x[7] ^= (x[5] & x[6]);
    x[4] ^= (x[5] & x[7]);
    x[5] ^= (x[4] | x[3]);
    x[6] ^=  x[4];
    x[3] ^=  x[7];
    x[7] ^= (x[3] & x[6]);

    // S3
    x[0] ^= (x[2] & x[1]);
    x[1] ^= (x[2] | x[0]);
    x[1]  = ~x[1];
    x[2] ^= (x[0] | x[1]);

    // Extend XOR
    x[7] ^=  x[2];  x[6] ^=  x[1];  x[5] ^=  x[0];

    // S5_2
    T[0]  =  x[7];  T[1]  =  x[6];  T[2]  =  x[5];
    x[4] ^= (x[3] & T[0]);
    x[4] ^=  T[1];
    T[2] ^= (x[4] | T[1]);
    T[0] ^=  T[2];
    T[1] ^=  x[3];
    T[2] |=  T[1];
    x[3] ^= (x[4] | T[0]);
    T[2] ^=  T[0];

    // Truncated XOR
    x[2] ^= T[0];   x[1] ^= T[2];   x[0] ^= T[1];
}

void P_layer_128(uint16_t In_text[]){
    uint16_t *x = In_text;

    x[1] = ( (x[1] << 15) | (x[1] >> 1 ) );
    x[2] = ( (x[2] << 8 ) | (x[2] >> 8 ) );
    x[3] = ( (x[3] << 2 ) | (x[3] >> 14) );
    x[4] = ( (x[4] << 10) | (x[4] >> 6 ) );
    x[5] = ( (x[5] << 7 ) | (x[5] >> 9 ) );
    x[6] = ( (x[6] << 9 ) | (x[6] >> 7 ) );
    x[7] = ( (x[7] << 1 ) | (x[7] >> 15) );
}

void Inv_S_layer_128(uint16_t In_text[]){
    uint16_t *x = In_text; // Bit_slide pointer of Plaintext
    uint16_t T[4]; // Temporary value
    // Inv_S5_2
    T[0]  =  x[7];  T[1]  =  x[6];  T[2]  =  x[5];  T[3]  =  T[0];
    T[2] ^= (x[4] | T[1]);
    T[0] ^=  T[2];
    x[3] ^= (x[4] | T[0]);
    x[4] ^=  T[1];
    T[1] ^=  x[3];
    T[2] |=  T[1];
    T[2] ^=  T[0];
    x[4] ^= (x[3] & T[3]);

    // Truncated XOR
    x[2] ^=  T[0];  x[1] ^=  T[2];  x[0] ^=  T[1];

    // Extend XOR
    x[7] ^=  x[2];   x[6] ^=  x[1];   x[5] ^=  x[0];

    // Inv_S5_1
    x[7] ^= (x[3] & x[6]);
    x[3] ^=  x[7];
    x[6] ^=  x[4];
    x[5] ^= (x[4] | x[3]);
    x[4] ^= (x[5] & x[7]);
    x[7] ^= (x[5] & x[6]);

    // Inv_S3
    x[2] ^= (x[0] | x[1]);
    x[1]  = ~x[1];
    x[1] ^= (x[2] | x[0]);
    x[0] ^= (x[2] & x[1]);
}

void Inv_P_layer_128(uint16_t In_text[]){
    uint16_t *x = In_text;

    x[1] = ( (x[1] << 1 ) | (x[1] >> 15) );
    x[2] = ( (x[2] << 8 ) | (x[2] >> 8 ) );
    x[3] = ( (x[3] << 14) | (x[3] >> 2 ) );
    x[4] = ( (x[4] << 6 ) | (x[4] >> 10) );
    x[5] = ( (x[5] << 9 ) | (x[5] >> 7 ) );
    x[6] = ( (x[6] << 7 ) | (x[6] >> 9 ) );
    x[7] = ( (x[7] << 15) | (x[7] >> 1 ) );
}

void Key_XOR_128_256(uint16_t In_text[], uint16_t Key[], uint16_t Round){
        In_text[0] ^= Round;
        int i;
        if (Round % 2){
                for (i = 0; i < 8; ++i)
                        In_text[i] ^= Key[i+8];
        }

        else{
                for (i = 0; i < 8; ++i)
                        In_text[i] ^= Key[i];
        }
}

void PIPO_128_256_D_C(uint16_t Plaintext[], uint16_t Key[], uint16_t Ciphertext[]){
    uint16_t i;
    uint16_t temp[8];
    for (i = 0; i < 8; ++i)
        temp[i] = Ciphertext[i];

    for (i = 21; i > 0 ; --i)
    {
        Key_XOR_128_256(temp,Key,i);
        Inv_P_layer_128(temp);
        Inv_S_layer_128(temp);
    }

    for (i = 0; i < 8; ++i)
        Plaintext[i] = temp[i] ^ Key[i];
}
