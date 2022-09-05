#include "AES.cpp"

int main(int argc, char const *argv[])
{
    char filepath[50];
    char decryptkey[50];
    if(argv[1]!=NULL)
    {
        strcpy(filepath,argv[1]);
        strcpy(decryptkey,argv[2]);
    }
    else
    {
        strcpy(filepath ,"./encrypt_img.bmp");
        cout<<"Input the key\n";
        cin>>decryptkey;
    }
    struct Imgraw img = {0, 0, 0, NULL};
    AES_Init();
    bmpRead(filepath, &img.data, &img.width, &img.height, &img.bits);

    int len = strlen(decryptkey);
    int keyLen=(len<=16)?16:(len<=24)?24:32;
    uint8_t key[16 *(10+(keyLen-10)%6) + 1]= {0};
    for(int i=0; i < keyLen; i++)
    {
        if(i<len)
            key[i] = int(decryptkey[i]);
        else
            key[i]=0;
    }
    int expandKeyLen = AES_ExpandKey(key, keyLen);
    uint8_t block[16]= {0};

    for(int i = 0;i<ori_rawdata.size();i+=16)
    {
        for(int j=0;j<16;j++)
        {
            if((i+j) < (ori_rawdata.size()))
                block[j]=int(ori_rawdata.at(i+j));
            else
                block[j]=0;
        }
        AES_Decrypt(block, key, expandKeyLen);
        for(int j = 0;j<16;j++)
        {
            if((i+j) < (ori_rawdata.size()))
                ori_rawdata[i+j]=block[j];
        }

    }

    bmpWrite("decrypt_img.bmp", img.data, img.width, img.height, img.bits);
    AES_Done();
    return 0;
}


