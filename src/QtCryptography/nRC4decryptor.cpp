#include <qtcryptography>
#include <openssl/rc4.h>

N::Decrypt::Rc4:: Rc4       (void)
                : Decryptor (    )
{
}

N::Decrypt::Rc4::~Rc4 (void)
{
}

bool N::Decrypt::Rc4::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Decrypt::Rc4::type(void) const
{
  return 100009 ;
}

QString N::Decrypt::Rc4::name(void)
{
  return QString("RC4") ;
}

QStringList N::Decrypt::Rc4::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Decrypt::Rc4::Bits(void)
{
  CUIDs IDs                ;
  for (int i=8;i<=128;i++) {
    IDs << ( i * 8 )       ;
  }                        ;
  return IDs               ;
}

bool N::Decrypt::Rc4::decrypt(QByteArray & input,QByteArray & output)
{
  if (Key.size()!=(48+sizeof(RC4_KEY))) return false      ;
  /////////////////////////////////////////////////////////
  unsigned char * y = (unsigned char *)Key.data()         ;
  char          * z = (char          *)Key.data()         ;
  /////////////////////////////////////////////////////////
  int             T        = ((int          *)y)[0]       ;
  if ( T != type() ) return false                         ;
  /////////////////////////////////////////////////////////
  int             keySize  = ((int          *)y)[4]       ;
  if ( keySize != input.size() ) return false             ;
  /////////////////////////////////////////////////////////
  unsigned int    keyAdler = ((unsigned int *)y)[2]       ;
  unsigned int    inpAdler = ADLER32 ( input  , 0 )       ;
  if ( keyAdler != inpAdler ) return false                ;
  /////////////////////////////////////////////////////////
  unsigned int srcAdler = ((unsigned int *)y)[1]          ;
  int          srcSize  = ((int          *)y)[3]          ;
  if (srcSize!=keySize) return false                      ;
  output . resize ( srcSize )                             ;
  /////////////////////////////////////////////////////////
  unsigned char * inp = NULL                              ;
  unsigned char * oup = NULL                              ;
  inp = (unsigned char *) input  . data ( )               ;
  oup = (unsigned char *) output . data ( )               ;
  /////////////////////////////////////////////////////////
  RC4_KEY K2                                              ;
  memcpy ( &K2 , z + 48 , sizeof(RC4_KEY) )               ;
  ::RC4  ( &K2 , keySize , inp , oup )                    ;
  /////////////////////////////////////////////////////////
  unsigned int decAdler = ADLER32 ( output  , 0 )         ;
  if ( decAdler != srcAdler) return false                 ;
  return true                                             ;
}
