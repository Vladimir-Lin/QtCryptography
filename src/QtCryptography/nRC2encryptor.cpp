#include <qtcryptography>
#include <openssl/rc2.h>

N::Encrypt::Rc2:: Rc2       (void)
                : Encryptor (    )
{
}

N::Encrypt::Rc2::~Rc2 (void)
{
}

bool N::Encrypt::Rc2::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Encrypt::Rc2::type(void) const
{
  return 100008 ;
}

QString N::Encrypt::Rc2::name(void)
{
  return QString("RC2") ;
}

QStringList N::Encrypt::Rc2::Methods(void)
{
  QStringList E ;
  E << "CBC"    ;
  E << "ECB"    ;
//  E << "CFB"    ;
//  E << "OFB"    ;
  return E      ;
}

CUIDs N::Encrypt::Rc2::Bits(void)
{
  CUIDs  IDs               ;
  for (int i=1;i<=128;i++) {
    IDs << ( i * 8 )       ;
  }                        ;
  return IDs               ;
}

bool N::Encrypt::Rc2::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3) return false                  ;
  if (input    .size ()<=0) return false                  ;
  /////////////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()                     ;
  if ((bits%8)!=0  ) return false                         ;
  if ((bits/8)<=0  ) return false                         ;
  if ((bits/8)> 128) return false                         ;
  /////////////////////////////////////////////////////////
  bool    correct = false                                 ;
  QString mode = Arguments[1].toString()                  ;
  mode    = mode.toUpper()                                ;
  if (mode=="ECB") correct = true                         ;
  if (mode=="CBC") correct = true                         ;
  if (mode=="CFB") correct = true                         ;
  if (mode=="OFB") correct = true                         ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString       key = Arguments[2].toString()             ;
  unsigned char k[256]                                    ;
  CopyKey ( key , k , 256 )                               ;
  /////////////////////////////////////////////////////////
  RC2_KEY K                                               ;
  unsigned char IV[1024]                                  ;
  memset ( IV , 0 , 1024 )                                ;
  :: RC2_set_key ( &K , key.length() , k , bits )         ;
  /////////////////////////////////////////////////////////
  int              len   = input.size()                   ;
  int              index = 0                              ;
  unsigned char *  d     = (unsigned char *)input.data()  ;
  output . clear ( )                                      ;
  if (mode=="ECB")                                        {
    unsigned char   o[16]                                 ;
    unsigned char   x[16]                                 ;
    while (index<len)                                     {
      int ds = len - index                                ;
      if (ds>8) ds = 8                                    ;
      memset ( o , 0 , 16 )                               ;
      memset ( x , 0 , 16 )                               ;
      memcpy ( x , d , ds )                               ;
      ::RC2_ecb_encrypt ( x , o , &K , RC2_ENCRYPT      ) ;
      output . append   ( (const char *)o , 8           ) ;
      d     += 8                                          ;
      index += 8                                          ;
    }                                                     ;
  } else
  if (mode=="CBC")                                        {
    unsigned char * o                                     ;
    output . resize ( len )                               ;
    o = (unsigned char *) output . data ( )               ;
    ::RC2_cbc_encrypt ( d,o,len,&K,IV,RC2_ENCRYPT       ) ;
  } else
  if (mode=="CFB")                                        {
//      void RC2_cfb64_encrypt(const unsigned char *in, unsigned char *out,long length, RC2_KEY *schedule, unsigned char *ivec,int *num, int enc);
  } else
  if (mode=="OFB")                                        {
//      void RC2_ofb64_encrypt(const unsigned char *in, unsigned char *out,long length, RC2_KEY *schedule, unsigned char *ivec,int *num);
  }                                                       ;
  if (output.size()<=0) return false                      ;
  /////////////////////////////////////////////////////////
  Key . resize ( 288 )                                    ;
  unsigned char * y = (unsigned char *)Key.data()         ;
  char          * z = (char          *)Key.data()         ;
  memset ( y , 0 , 288 )                                  ;
  ((int          *)y)[0] = type    (            )         ;
  ((unsigned int *)y)[1] = ADLER32 ( input  , 0 )         ;
  ((unsigned int *)y)[2] = ADLER32 ( output , 0 )         ;
  ((int          *)y)[3] = input  . size ( )              ;
  ((int          *)y)[4] = output . size ( )              ;
  ((int          *)y)[5] = bits                           ;
  strcpy ( z + 28 , mode.toUtf8().constData() )           ;
  memcpy ( z + 32 , k , 256                   )           ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
