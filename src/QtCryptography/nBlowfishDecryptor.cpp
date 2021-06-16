#include <qtcryptography>
#include <openssl/blowfish.h>

N::Decrypt::Blowfish:: Blowfish  (void)
                     : Decryptor (    )
{
}

N::Decrypt::Blowfish::~Blowfish (void)
{
}

bool N::Decrypt::Blowfish::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Decrypt::Blowfish::type(void) const
{
  return 100005 ;
}

QString N::Decrypt::Blowfish::name(void)
{
  return QString("Blowfish") ;
}

QStringList N::Decrypt::Blowfish::Methods(void)
{
  QStringList E ;
  E << "CBC"    ;
  E << "ECB"    ;
//  E << "CFB"    ;
//  E << "OFB"    ;
  return E      ;
}

CUIDs N::Decrypt::Blowfish::Bits(void)
{
  CUIDs IDs  ;
  IDs << 64  ;
  return IDs ;
}

bool N::Decrypt::Blowfish::decrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3)                               {
    if (Key.size()!=96) return false                      ;
    unsigned char * y = (unsigned char *)Key.data()       ;
    char          * z = (char          *)Key.data()       ;
    if (type()!=(((int*)y)[0])) return false              ;
    if (Arguments.count()<1)                              {
      Arguments << ((int          *)y)[5]                 ;
    }                                                     ;
    if (Arguments.count()<2)                              {
      QByteArray S                                        ;
      S.append(z+32,16)                                   ;
      S.resize(3)                                         ;
      Arguments << QString::fromUtf8(S)                   ;
    }                                                     ;
    if (Arguments.count()<3)                              {
      QByteArray S                                        ;
      S.append(z+64,32)                                   ;
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
  if (bits==64) correct = true                            ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString mode = Arguments[1].toString()                  ;
  mode    = mode.toUpper()                                ;
  correct = false                                         ;
  if (mode=="CBC"      ) correct = true                   ;
  if (mode=="ECB"      ) correct = true                   ;
  /////////////////////////////////////////////////////////
  QString       key = Arguments[2].toString()             ;
  QByteArray    K   = key.toUtf8()                        ;
  unsigned char k[32]                                     ;
  memset ( k , ' ' , 32 )                                 ;
  if (K.size()>0)                                         {
    int L = K.size()                                      ;
    if (L>32) L = 32                                      ;
    memcpy ( k , K.constData() , L )                      ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  BF_KEY K1                                               ;
  ::BF_set_key ( &K1 , 16 , k )                           ;
  /////////////////////////////////////////////////////////
  int             len   = input.size()                    ;
  int             index = 0                               ;
  unsigned char * d     = (unsigned char *)input.data()   ;
  output . clear ( )                                      ;
  if (mode=="ECB")                                        {
    unsigned char   o[16]                                 ;
    unsigned char   x[16]                                 ;
    while (index<len)                                     {
      int ds = len - index                                ;
      if (ds>8) ds = 8                                    ;
      memset           ( o , 0 , 16               )       ;
      memset           ( x , 0 , 16               )       ;
      memcpy           ( x , d , ds               )       ;
      ::BF_ecb_encrypt ( x , o , &K1 , BF_DECRYPT )       ;
      output . append  ( (const char *)o , 8 )            ;
      d     += 8                                          ;
      index += 8                                          ;
    }                                                     ;
  } else
  if (mode=="CBC")                                        {
    unsigned char iv[64]                                  ;
    unsigned char * o                                     ;
    memset           ( iv , 0 , 64               )        ;
    output . resize  ( len                       )        ;
    o = (unsigned char *)output.data()                    ;
    ::BF_cbc_encrypt ( d,o,len,&K1,iv,BF_DECRYPT )        ;
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
