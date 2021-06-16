#include <qtcryptography>
#include <openssl/aes.h>

N::Encrypt::Aes:: Aes       (void)
                : Encryptor (    )
{
}

N::Encrypt::Aes::~Aes (void)
{
}

bool N::Encrypt::Aes::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Encrypt::Aes::type(void) const
{
  return 100001 ;
}

QString N::Encrypt::Aes::name(void)
{
  return QString("AES") ;
}

QStringList N::Encrypt::Aes::Methods(void)
{
  QStringList E ;
  E << "CBC"    ;
  E << "ECB"    ;
//  E << "CFB"    ;
//  E << "OFB"    ;
  return E      ;
}

CUIDs N::Encrypt::Aes::Bits(void)
{
  CUIDs  IDs ;
  IDs << 128 ;
  IDs << 192 ;
  IDs << 256 ;
  return IDs ;
}

bool N::Encrypt::Aes::encrypt(QByteArray & input,QByteArray & output)
{
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
  if (::AES_set_encrypt_key(k,bits,&aes)<0) return false  ;
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
      ::AES_ecb_encrypt ( x , o , &aes , AES_ENCRYPT )    ;
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
    ::AES_cbc_encrypt ( d,o,len,&aes,iv,AES_ENCRYPT )     ;
  }                                                       ;
  if (output.size()<=0) return false                      ;
  /////////////////////////////////////////////////////////
  Key . resize ( 64 )                                     ;
  unsigned char * y = (unsigned char *)Key.data()         ;
  char          * z = (char          *)Key.data()         ;
  memset ( y , 0 , 64 )                                   ;
  ((int          *)y)[0] = type    (            )         ;
  ((unsigned int *)y)[1] = ADLER32 ( input  , 0 )         ;
  ((unsigned int *)y)[2] = ADLER32 ( output , 0 )         ;
  ((int          *)y)[3] = input  . size ( )              ;
  ((int          *)y)[4] = output . size ( )              ;
  ((int          *)y)[5] = bits                           ;
  strcpy ( z + 28 , mode.toUtf8().constData() )           ;
  memcpy ( z + 32 , k , 32                    )           ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
