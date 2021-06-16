#include <qtcryptography>
#include <openssl/blowfish.h>

N::Encrypt::Blowfish:: Blowfish  (void)
                     : Encryptor (    )
{
}

N::Encrypt::Blowfish::~Blowfish (void)
{
}

bool N::Encrypt::Blowfish::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Encrypt::Blowfish::type(void) const
{
  return 100005 ;
}

QString N::Encrypt::Blowfish::name(void)
{
  return QString("Blowfish") ;
}

QStringList N::Encrypt::Blowfish::Methods(void)
{
  QStringList E ;
  E << "CBC"    ;
  E << "ECB"    ;
//  E << "CFB"    ;
//  E << "OFB"    ;
  return E      ;
}

CUIDs N::Encrypt::Blowfish::Bits(void)
{
  CUIDs  IDs ;
  IDs << 64  ;
  return IDs ;
}

bool N::Encrypt::Blowfish::encrypt(QByteArray & input,QByteArray & output)
{
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
  if (mode=="CBC") correct = true                         ;
  if (mode=="ECB") correct = true                         ;
//  if (mode=="CFB") correct = true                         ;
//  if (mode=="OFB") correct = true                         ;
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
      memset           ( o , 0 , 16          )            ;
      memset           ( x , 0 , 16          )            ;
      memcpy           ( x , d , ds          )            ;
      ::BF_ecb_encrypt ( x,o,&K1,BF_ENCRYPT  )            ;
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
    ::BF_cbc_encrypt ( d,o,len,&K1,iv,BF_ENCRYPT )        ;
  }                                                       ;
  if (output.size()<=0) return false                      ;
  /////////////////////////////////////////////////////////
  Key . resize ( 96 )                                     ;
  unsigned char * y = (unsigned char *)Key.data()         ;
  char          * z = (char          *)Key.data()         ;
  memset ( y , 0 , 96 )                                   ;
  ((int          *)y)[0] = type    (            )         ;
  ((unsigned int *)y)[1] = ADLER32 ( input  , 0 )         ;
  ((unsigned int *)y)[2] = ADLER32 ( output , 0 )         ;
  ((int          *)y)[3] = input  . size ( )              ;
  ((int          *)y)[4] = output . size ( )              ;
  ((int          *)y)[5] = bits                           ;
  strcpy ( z + 32 , mode.toUtf8().constData() )           ;
  memcpy ( z + 64 , k , 32                    )           ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
