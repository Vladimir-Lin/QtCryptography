#include <qtcryptography>
#include <openssl/aes.h>

N::Decrypt::Aes:: Aes       (void)
                : Decryptor (    )
{
}

N::Decrypt::Aes::~Aes (void)
{
}

bool N::Decrypt::Aes::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Decrypt::Aes::type(void) const
{
  return 100001 ;
}

QString N::Decrypt::Aes::name(void)
{
  return QString("AES") ;
}

QStringList N::Decrypt::Aes::Methods(void)
{
  QStringList E ;
  E << "CBC"    ;
  E << "ECB"    ;
//  E << "CFB"    ;
//  E << "OFB"    ;
  return E      ;
}

CUIDs N::Decrypt::Aes::Bits(void)
{
  CUIDs  IDs ;
  IDs << 128 ;
  IDs << 192 ;
  IDs << 256 ;
  return IDs ;
}

bool N::Decrypt::Aes::decrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3)                               {
    if (Key.size()!=64) return false                      ;
    unsigned char * y = (unsigned char *)Key.data()       ;
    char          * z = (char          *)Key.data()       ;
    if (type()!=(((int*)y)[0])) return false              ;
    if (Arguments.count()<1)                              {
      Arguments << ((int          *)y)[5]                 ;
    }                                                     ;
    if (Arguments.count()<2)                              {
      QByteArray S                                        ;
      S.append(z+28,3)                                    ;
      Arguments << QString::fromUtf8(S)                   ;
    }                                                     ;
    if (Arguments.count()<3)                              {
      QByteArray S                                        ;
      S.append(z+32,32)                                   ;
      Arguments << QString::fromUtf8(S)                   ;
    }                                                     ;
    if (Arguments.count()<4)                              {
      Arguments << ((unsigned int *)y)[1]                 ;
    }                                                     ;
    if (Arguments.count()<5)                              {
      Arguments << ((unsigned int *)y)[2]                 ;
    }                                                     ;
    if (Arguments.count()<6)                              {
      Arguments << ((int          *)y)[3]                 ;
    }                                                     ;
    if (Arguments.count()<7)                              {
      Arguments << ((int          *)y)[4]                 ;
    }                                                     ;
  }                                                       ;
  if (Arguments.count()< 3) return false                  ;
  if (input    .size ()<=0) return false                  ;
  /////////////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()                     ;
  bool correct = false                                    ;
  if (bits==128) correct = true                           ;
  if (bits==192) correct = true                           ;
  if (bits==256) correct = true                           ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString mode = Arguments[1].toString()                  ;
  mode    = mode.toUpper()                                ;
  correct = false                                         ;
  if (mode=="ECB") correct = true                         ;
  if (mode=="CBC") correct = true                         ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString       key = Arguments[2].toString()             ;
  unsigned char k[32]                                     ;
  CopyKey ( key , k , 32 )                                ;
  /////////////////////////////////////////////////////////
  AES_KEY aes                                             ;
  if (::AES_set_decrypt_key(k,bits,&aes)<0) return false  ;
  /////////////////////////////////////////////////////////
  int             len   = input.size()                    ;
  int             index = 0                               ;
  unsigned char * d     = (unsigned char *)input.data()   ;
  output . clear ( )                                      ;
  if (mode=="ECB")                                        {
    unsigned char   o[64]                                 ;
    unsigned char   x[64]                                 ;
    while (index<len)                                     {
      int ds = len - index                                ;
      if (ds>16) ds = 16                                  ;
      memset ( o , 0 , 64 )                               ;
      memset ( x , 0 , 64 )                               ;
      memcpy ( x , d , ds )                               ;
      ::AES_ecb_encrypt ( x , o , &aes , AES_DECRYPT )    ;
      output . append   ( (const char *)o , 16       )    ;
      d     += 16                                         ;
      index += 16                                         ;
    }                                                     ;
  } else
  if (mode=="CBC")                                        {
    unsigned char iv[64]                                  ;
    memset ( iv , 0 , 64 )                                ;
    output.resize(input.size())                           ;
    unsigned char * o = (unsigned char *)output.data()    ;
    ::AES_cbc_encrypt ( d,o,len,&aes,iv,AES_DECRYPT )     ;
  }                                                       ;
  if (output.size()<=0) return false                      ;
  /////////////////////////////////////////////////////////
  if (Arguments.count()>5)                                {
    int ics = Arguments[5].toInt()                        ;
    output . resize ( ics )                               ;
  }                                                       ;
  if (Arguments.count()>6)                                {
    int ics = Arguments[6].toInt()                        ;
    if (ics!=input.size()) return false                   ;
  }                                                       ;
  if (Arguments.count()>3)                                {
    unsigned int ics = Arguments[3].toUInt()              ;
    unsigned int ocs = ADLER32(output,0)                  ;
    if (ics!=ocs) return false                            ;
  }                                                       ;
  if (Arguments.count()>4)                                {
    unsigned int ics = Arguments[4].toUInt()              ;
    unsigned int ocs = ADLER32(input ,0)                  ;
    if (ics!=ocs) return false                            ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
