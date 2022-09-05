#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>

using namespace std;

#pragma pack(2)
struct BmpFileHeader
{
    uint16_t bfTybe;
    uint32_t bfSize;
    uint16_t bfReserved1;
    uint16_t bfReserved2;//保留欄位共4 bytes
    uint32_t bfOffBits;//bitmap data offset
};
struct BmpInfoHeader
{
    uint32_t biSize;
    uint32_t biWidth; //pixel
    uint32_t biHeight; //pixel
    uint16_t biPlanes; // 1=defeaul, 0=custom
    uint16_t biBitCount;//Bits per pixel
    uint32_t biCompression;//0 -> none
    uint32_t biSizeImage;//bitmap data size
    uint32_t biXPelsPerMeter; // 72dpi=2835, 96dpi=3780 水平解析度
    uint32_t biYPelsPerMeter; // 120dpi=4724, 300dpi=11811 垂直解析度
    uint32_t biClrUsed;// Used color
    uint32_t biClrImportant;//important colors
};
#pragma pack()
//total :54 bytes
struct Imgraw
{
    uint32_t width, height;
    uint16_t bits;
    uint8_t* data;
};


uint8_t AES_Sbox[]={
	223,117,160,216,61,114,238,38,241,48,44,214,181,60,56,183,97,206,171,1,
	72,89,39,88,143,54,237,74,91,205,46,185,173,40,106,147,70,10,83,47,19,151,101,123,18,138,
	16,5,35,12,13,36,152,245,213,176,113,190,45,41,69,191,71,164,116,63,193,85,208,167,67,199,161,
	27,170,6,84,234,22,7,187,203,226,130,112,179,253,0,3,30,163,133,107,102,225,148,141,62,25,137,
	224,166,52,220,121,204,228,182,26,135,255,82,215,227,254,212,157,118,119,168,96,11,239,149,247,
	57,105,134,218,132,150,250,174,90,51,58,233,248,32,128,31,180,189,209,115,95,219,162,246,231,195,
	65,81,53,196,98,4,78,126,146,129,42,24,175,120,131,178,192,2,124,59,93,20,50,188,87,169,33,79,99,
	232,158,210,122,100,172,211,68,156,125,243,108,200,217,49,197,55,154,111,186,37,252,64,77,155,177,
	201,184,222,73,15,194,153,127,104,80,103,249,202,8,235,14,17,28,9,159,244,145,240,221,86,76,144,140,
	251,230,236,75,34,43,109,94,198,139,207,21,165,92,66,110,242,142,29,229,136,23
};

uint8_t AES_ShiftRowTab[] = {0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11};//16
uint8_t AES_Sbox_Inv[256];
uint8_t AES_ShiftRowTab_Inv[16];
uint8_t AES_xtime[256];
vector<uint8_t> ori_rawdata;

void AES_SubBytes(uint8_t state[], uint8_t sbox[])
{
    int i;
    for(i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

void AES_AddRoundKey(uint8_t state[], uint8_t rkey[])
{
    int i;
    for(i = 0; i < 16; i++)
        state[i] ^= rkey[i];
}

void AES_ShiftRows(uint8_t state[], uint8_t shifttab[])
{
    uint8_t h[16];
    memcpy(h, state, 16);
    int i;
    for(i = 0; i < 16; i++)
        state[i] = h[shifttab[i]];
}

void AES_MixColumns(uint8_t state[])
{
    int i;
    for(i = 0; i < 16; i += 4)
    {
        uint8_t s0 = state[i + 0], s1 = state[i + 1];
        uint8_t s2 = state[i + 2], s3 = state[i + 3];
        uint8_t h = s0 ^ s1 ^ s2 ^ s3;
        state[i + 0] ^= h ^ AES_xtime[s0 ^ s1];
        state[i + 1] ^= h ^ AES_xtime[s1 ^ s2];
        state[i + 2] ^= h ^ AES_xtime[s2 ^ s3];
        state[i + 3] ^= h ^ AES_xtime[s3 ^ s0];
    }
}

void AES_MixColumns_Inv(uint8_t state[])
{
    int i;
    for(i = 0; i < 16; i += 4)
    {
        uint8_t s0 = state[i + 0], s1 = state[i + 1];
        uint8_t s2 = state[i + 2], s3 = state[i + 3];
        uint8_t h = s0 ^ s1 ^ s2 ^ s3;
        uint8_t xh = AES_xtime[h];
        uint8_t h1 = AES_xtime[AES_xtime[xh ^ s0 ^ s2]] ^ h;
        uint8_t h2 = AES_xtime[AES_xtime[xh ^ s1 ^ s3]] ^ h;
        state[i + 0] ^= h1 ^ AES_xtime[s0 ^ s1];
        state[i + 1] ^= h2 ^ AES_xtime[s1 ^ s2];
        state[i + 2] ^= h1 ^ AES_xtime[s2 ^ s3];
        state[i + 3] ^= h2 ^ AES_xtime[s3 ^ s0];
    }
}

// AES_Init: initialize the tables needed at runtime.
// Call this function before the (first) key expansion.
void AES_Init()
{
    int i;
    for(i = 0; i < 256; i++)
        AES_Sbox_Inv[AES_Sbox[i]] = i;

    for(i = 0; i < 16; i++)
        AES_ShiftRowTab_Inv[AES_ShiftRowTab[i]] = i;

    for(i = 0; i < 128; i++)
    {
        AES_xtime[i] = i << 1;
        AES_xtime[128 + i] = (i << 1) ^ 0x1b;
    }
}

// AES_Done: release memory reserved by AES_Init.
// Call this function after the last encryption/decryption operation.
void AES_Done()
{
    cout<<"Convert successfully!\n";
}

/* AES_ExpandKey: expand a cipher key. Depending on the desired encryption
   strength of 128, 192 or 256 bits 'key' has to be a byte array of length
   16, 24 or 32, respectively. The key expansion is done "in place", meaning
   that the array 'key' is modified.
*/
int AES_ExpandKey(uint8_t key[], int keyLen)
{
    int kl = keyLen, ks, Rcon = 1, i, j;
    uint8_t temp[4], temp2[4];
    switch (kl)
    {
    case 16:
        ks = 16 * (10 + 1);
        break;
    case 24:
        ks = 16 * (12 + 1);
        break;
    case 32:
        ks = 16 * (14 + 1);
        break;
    default:
        cout<<"AES_ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!";
    }
    for(i = kl; i < ks; i += 4)
    {
        memcpy(temp, &key[i-4], 4);
        if (i % kl == 0)
        {
            temp2[0] = AES_Sbox[temp[1]] ^ Rcon;
            temp2[1] = AES_Sbox[temp[2]];
            temp2[2] = AES_Sbox[temp[3]];
            temp2[3] = AES_Sbox[temp[0]];
            memcpy(temp, temp2, 4);
            if ((Rcon <<= 1) >= 256)
                Rcon ^= 0x11b;
        }
        else if ((kl > 24) && (i % kl == 16))
        {
            temp2[0] = AES_Sbox[temp[0]];
            temp2[1] = AES_Sbox[temp[1]];
            temp2[2] = AES_Sbox[temp[2]];
            temp2[3] = AES_Sbox[temp[3]];
            memcpy(temp, temp2, 4);
        }
        for(j = 0; j < 4; j++)
            key[i + j] = key[i + j - kl] ^ temp[j];
    }
    return ks;
}

// AES_Encrypt: encrypt the 16 byte array 'block' with the previously expanded key 'key'.
void AES_Encrypt(uint8_t block[], uint8_t key[], int keyLen)
{
    int l = keyLen, i;
    AES_AddRoundKey(block, &key[0]);
    for(i = 16; i < l - 16; i += 16)
    {
        AES_SubBytes(block, AES_Sbox);
        AES_ShiftRows(block, AES_ShiftRowTab);
        AES_MixColumns(block);
        AES_AddRoundKey(block, &key[i]);
    }
    AES_SubBytes(block, AES_Sbox);
    AES_ShiftRows(block, AES_ShiftRowTab);
    AES_AddRoundKey(block, &key[i]);
}

// AES_Decrypt: decrypt the 16 byte array 'block' with the previously expanded key 'key'.
void AES_Decrypt(uint8_t block[], uint8_t key[], int keyLen)
{
    int l = keyLen, i;
    AES_AddRoundKey(block, &key[l - 16]);
    AES_ShiftRows(block, AES_ShiftRowTab_Inv);
    AES_SubBytes(block, AES_Sbox_Inv);
    for(i = l - 32; i >= 16; i -= 16)
    {
        AES_AddRoundKey(block, &key[i]);
        AES_MixColumns_Inv(block);
        AES_ShiftRows(block, AES_ShiftRowTab_Inv);
        AES_SubBytes(block, AES_Sbox_Inv);
    }
    AES_AddRoundKey(block, &key[0]);
}

//**************************************************************

void bmpWrite(const char* name,  uint8_t* raw_img,
              uint32_t width, uint32_t height, uint16_t bits)
{
    string str="";
    if(!(name && raw_img))
    {
        perror("Error bmpWrite.");
        return;
    }
    // 檔案資訊
    struct BmpFileHeader file_h;
    file_h.bfTybe=0x4d42;
    file_h.bfReserved1=0;
    file_h.bfReserved2=0;
    file_h.bfOffBits=54;
    file_h.bfSize = file_h.bfOffBits + width*height * bits/8;
    if(bits==8)
    {
        file_h.bfSize += 1024, file_h.bfOffBits += 1024;
    }
    // 圖片資訊
    struct BmpInfoHeader info_h;
    info_h.biSize=40;
    info_h.biPlanes=1;
    info_h.biCompression=0;
    info_h.biXPelsPerMeter=0;
    info_h.biYPelsPerMeter=0;
    info_h.biClrUsed=0;
    info_h.biClrImportant=0;

    info_h.biWidth = width;
    info_h.biHeight = height;
    info_h.biBitCount = bits;
    info_h.biSizeImage = width*height * bits/8;
    if(bits == 8)
    {
        info_h.biClrUsed=256;
    }
    // 寫入檔頭
    FILE *pFile = fopen(name,"wb+");
    if(!pFile)
    {
        perror("Error opening file.");
        return;
    }
    fwrite((char*)&file_h, sizeof(char), sizeof(file_h), pFile);
    fwrite((char*)&info_h, sizeof(char), sizeof(info_h), pFile);
    // 寫調色盤

    if(bits == 8)
    {
        for(unsigned i = 0; i < 256; ++i)
        {
            uint8_t c = i;
            fwrite((char*)&c, sizeof(char), sizeof(uint8_t), pFile);
            fwrite((char*)&c, sizeof(char), sizeof(uint8_t), pFile);
            fwrite((char*)&c, sizeof(char), sizeof(uint8_t), pFile);
            fwrite("", sizeof(char), sizeof(uint8_t), pFile);
        }
    }

    // 寫入圖片資訊
    int count=0;
    size_t alig = ((width*bits/8)*3) % 4;
    for(int j = height-1; j >= 0; --j)
    {
        for(unsigned i = 0; i < width; ++i)
        {

            if(bits == 24)
            {
                raw_img[(j*width+i)*3 + 2]=int(ori_rawdata.at(count));
                fwrite((char*)&raw_img[(j*width+i)*3 + 2], sizeof(char), sizeof(uint8_t), pFile);//B
                count++;
                raw_img[(j*width+i)*3 + 1]=int(ori_rawdata.at(count));
                fwrite((char*)&raw_img[(j*width+i)*3 + 1], sizeof(char), sizeof(uint8_t), pFile);//G
                count++;
                raw_img[(j*width+i)*3 + 0]=int(ori_rawdata.at(count));
                fwrite((char*)&raw_img[(j*width+i)*3 + 0], sizeof(char), sizeof(uint8_t), pFile);//R
                count++;
            }
            else if(bits == 8)
            {
                fwrite((char*)&raw_img[j*width+i], sizeof(char), sizeof(uint8_t), pFile);
            }

        }
        // 對齊4byte
        for(size_t i = 0; i < alig; ++i)
        {
            fwrite("", sizeof(char), sizeof(uint8_t), pFile);
        }
    }

    fclose(pFile);
}

/* *********************************************************************************************************** */

void bmpRead(const char* name, uint8_t** raw_img,
             uint32_t* width, uint32_t* height, uint16_t* bits)
{
    if(!(name && raw_img && width && height && bits))
    {
        perror("Error bmpRead.");
        return;
    }
    // 檔案資訊
    struct BmpFileHeader file_h;
    // 圖片資訊
    struct BmpInfoHeader info_h;
    // 讀取檔頭
    FILE *pFile = fopen(name,"rb+");
    if(!pFile)
    {
        perror("Error opening file.");
        return;
    }
    fread((char*)&file_h, sizeof(char), sizeof(file_h), pFile);
    fread((char*)&info_h, sizeof(char), sizeof(info_h), pFile);
    // 讀取長寬
    *width = info_h.biWidth;
    *height = info_h.biHeight;
    *bits = info_h.biBitCount;
    *raw_img = (uint8_t*)calloc((info_h.biWidth)*(info_h.biHeight)*3, sizeof(uint8_t));
    cout<<"raw img size: "<<(info_h.biWidth)*(info_h.biHeight)*3<<endl;
    // 讀取讀片資訊轉RAW檔資訊
    fseek(pFile,0,SEEK_END);
    cout<<"total size = "<<ftell(pFile)<<endl;
    // 修正資料開始處
    fseek(pFile, file_h.bfOffBits, SEEK_SET);
    size_t alig = ((info_h.biWidth*info_h.biBitCount/8)*3) % 4;
    for(int j = *height-1; j >= 0; --j)
    {
        for(unsigned i = 0; i < *width; ++i)
        {
            if(*bits == 24)
            {
                fread((char*)&(*raw_img)[(j*(*width)+i)*3 + 2], sizeof(char), sizeof(uint8_t), pFile);
                ori_rawdata.push_back(int((*raw_img)[(j*(*width)+i)*3 + 2]));
                fread((char*)&(*raw_img)[(j*(*width)+i)*3 + 1], sizeof(char), sizeof(uint8_t), pFile);
                ori_rawdata.push_back(int((*raw_img)[(j*(*width)+i)*3 + 1]));
                fread((char*)&(*raw_img)[(j*(*width)+i)*3 + 0], sizeof(char), sizeof(uint8_t), pFile);
                ori_rawdata.push_back(int((*raw_img)[(j*(*width)+i)*3 + 0]));
            }
            else if(*bits == 8)
            {
                fread((char*)&(*raw_img)[j*(*width)+i], sizeof(char), sizeof(uint8_t), pFile);
            }
        }
        fseek(pFile, alig, SEEK_CUR);
    }

    fclose(pFile);
}

void printBytes(uint8_t b[], int len)
{
    int i;
    for (i=0; i<len; i++)
        cout<<int(b[i])<<" ";
    cout<<endl;
}

/******************************************************************************/

