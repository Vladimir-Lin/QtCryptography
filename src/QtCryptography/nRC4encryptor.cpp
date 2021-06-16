#include <qtcryptography>
#include <openssl/rc4.h>

N::Encrypt::Rc4:: Rc4       (void)
                : Encryptor (    )
{
}

N::Encrypt::Rc4::~Rc4 (void)
{
}

bool N::Encrypt::Rc4::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Encrypt::Rc4::type(void) const
{
  return 100009 ;
}

QString N::Encrypt::Rc4::name(void)
{
  return QString("RC4") ;
}

QStringList N::Encrypt::Rc4::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Encrypt::Rc4::Bits(void)
{
  CUIDs IDs                ;
  for (int i=8;i<=128;i++) {
    IDs << ( i * 8 )       ;
  }                        ;
  return IDs               ;
}

bool N::Encrypt::Rc4::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3) return false                  ;
  if (input    .size ()<=0) return false                  ;
  /////////////////////////////////////////////////////////
  QString       key = Arguments[2].toString()             ;
  int           len = key.length()                        ;
  unsigned char k[256]                                    ;
  if (len>128) len = 128                                  ;
  CopyKey ( key , k , 256 )                               ;
  /////////////////////////////////////////////////////////
  unsigned char * inp = NULL                              ;
  unsigned char * oup = NULL                              ;
  int             dsv = input.size()                      ;
  output.resize(dsv)                                      ;
  inp = (unsigned char *) input  . data ( )               ;
  oup = (unsigned char *) output . data ( )               ;
  /////////////////////////////////////////////////////////
  RC4_KEY K1                                              ;
  RC4_KEY K2                                              ;
  ::RC4_set_key ( &K1 , len , k         )                 ;
  ::RC4_set_key ( &K2 , len , k         )                 ;
  ::RC4         ( &K1 , dsv , inp , oup )                 ;
  /////////////////////////////////////////////////////////
  Key . resize ( 48 + sizeof(RC4_KEY) )                   ;
  unsigned char * y = (unsigned char *)Key.data()         ;
  char          * z = (char          *)Key.data()         ;
  memset ( y , 0 , 48 + sizeof(RC4_KEY) )                 ;
  ((int          *)y)[0] = type    (            )         ;
  ((unsigned int *)y)[1] = ADLER32 ( input  , 0 )         ;
  ((unsigned int *)y)[2] = ADLER32 ( output , 0 )         ;
  ((int          *)y)[3] = input  . size ( )              ;
  ((int          *)y)[4] = output . size ( )              ;
  memcpy ( z + 48 , &K2 , sizeof(RC4_KEY)  )              ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
