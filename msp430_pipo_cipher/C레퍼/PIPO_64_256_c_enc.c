#include <stdio.h>

typedef unsigned char           uint8_t;
typedef unsigned short          uint16_t;
typedef unsigned int            uint32_t;
typedef unsigned long long      uint64_t;

//#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-
//Total Functions
void S_layer_64(uint8_t In_text[]);
void P_layer_64(uint8_t In_text[]);
void Inv_S_layer_64(uint8_t In_text[]);
void Inv_P_layer_64(uint8_t In_text[]);
void Key_XOR_64_256(uint8_t In_text[], uint8_t Key[], uint8_t Round);
void PIPO_64_256_E_C(uint8_t Plaintext[], uint8_t Key[], uint8_t Ciphertext[]);
//#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-


//#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-
//Specific Implementations
void S_layer_64(uint8_t In_text[]){
        uint8_t *x = In_text; // Bit_slide pointer of Plaintext
        uint8_t T[3]; // Temporary value
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

void P_layer_64(uint8_t In_text[]){
    uint8_t *x = In_text;
    x[1] = ((x[1] << 4) | (x[1] >> 4 ));
    x[2] = ((x[2] << 1) | (x[2] >> 7));
    x[3] = ((x[3] << 7) | (x[3] >> 1));
    x[4] = ((x[4] << 6) | (x[4] >> 2));
    x[5] = ((x[5] << 2) | (x[5] >> 6));
    x[6] = ((x[6] << 3) | (x[6] >> 5));
    x[7] = ((x[7] << 5) | (x[7] >> 3));
}

void Inv_S_layer_64(uint8_t In_text[]){
    uint8_t *x = In_text; // Bit_slide pointer of Plaintext
    uint8_t T[4]; // Temporary value
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
    x[2] ^=  T[0];  x[1] ^=  T[2];  x[2] ^=  T[1];

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

void Inv_P_layer_64(uint8_t In_text[]){
    uint8_t *x = In_text;
    x[1] = ((x[1] << 4) | (x[1] >> 4 ));
    x[2] = ((x[2] << 7) | (x[2] >> 1));
    x[3] = ((x[3] << 1) | (x[3] >> 7));
    x[4] = ((x[4] << 2) | (x[4] >> 6));
    x[5] = ((x[5] << 6) | (x[5] >> 2));
    x[6] = ((x[6] << 5) | (x[6] >> 3));
    x[7] = ((x[7] << 3) | (x[7] >> 5));
}

void Key_XOR_64_256(uint8_t In_text[], uint8_t Key[], uint8_t Round){
        In_text[0] ^= Round;
        int i;
        switch(Round % 4){
                case 0:
                        for (i = 0; i < 8; ++i)
                                In_text[i] ^= Key[i];
                        break;
                case 1:
                        for (i = 0; i < 8; ++i)
                                In_text[i] ^= Key[i+8];
                        break;
                case 2:
                        for (i = 0; i < 8; ++i)
                                In_text[i] ^= Key[i+16];
                        break;
                case 3:
                        for (i = 0; i < 8; ++i)
                                In_text[i] ^= Key[i+24];
        }
}

void PIPO_64_256_E_C(uint8_t Plaintext[], uint8_t Key[], uint8_t Ciphertext[]){
    uint8_t i;
    uint8_t temp[8];
    for (i = 0; i < 8; ++i)
        temp[i] = Plaintext[i]^Key[i];

    for (i = 1; i < 16; ++i)
    {
        S_layer_64(temp);
        P_layer_64(temp);
        Key_XOR_64_256(temp, Key, i);
    }

    for (i = 0; i < 8; ++i)
        Ciphertext[i] = temp[i];
}
