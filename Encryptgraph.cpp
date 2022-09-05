#include "AES.cpp"

int main(int argc, char const *argv[])
{
    char filepath[50];
    char encryptkey[50];
    if(argv[1]!=NULL)
    {
        strcpy(filepath,argv[1]);
        strcpy(encryptkey,argv[2]);
    }
    else
    {
        strcpy(filepath ,"./pic/Irene.bmp");
        cout<<"Input the key\n";
        cin>>encryptkey;
    }
    struct Imgraw img = {0, 0, 0, NULL};// width , height , bits , address of data
    bmpRead(filepath, &img.data, &img.width, &img.height, &img.bits);
    AES_Init();

    int len=strlen(encryptkey);
    if(len>32)
    {
        cout<<"Error! Input more than 32 \n";
        return 0;
    }
    int keyLen=(len<=16)?16:(len<=24)?24:32;
    cout<<"keylen= "<<keyLen<<endl;
    uint8_t key[16 *(10+(keyLen-10)%6) + 1]= {0};
    for(int i=0; i < keyLen; i++)
    {
        if(i<len)
            key[i] = int(encryptkey[i]);
        else
            key[i]=0;
    }
    cout<<endl;
    cout<<"orginal key  in integer is ";
    printBytes(key, keyLen);
    int expandKeyLen = AES_ExpandKey(key, keyLen);
    cout<<"extended key is\n";
    printBytes(key, expandKeyLen);
    int raw_size=ori_rawdata.size();
    uint8_t block[16]= {0};
    int i;

    for( i = 0;i<ori_rawdata.size();i+=16)
    {
        for(int j=0;j<16;j++)
        {
            if((i+j) < (ori_rawdata.size()))
                block[j]=ori_rawdata.at(i+j);
            else
                block[j]=0;
        }
        AES_Encrypt(block, key, expandKeyLen);
        for(int j = 0;j<16;j++)
        {
            if((i+j) < (ori_rawdata.size()))
                ori_rawdata[i+j]=block[j];
        }

    }

    bmpWrite("encrypt_img.bmp", img.data, img.width, img.height, img.bits);
    return 0;
}


