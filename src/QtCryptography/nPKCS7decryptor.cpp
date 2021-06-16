#include <qtcryptography>
#include <openssl/pkcs7.h>

N::Decrypt::Pkcs7:: Pkcs7     (void)
                  : Decryptor (    )
{
}

N::Decrypt::Pkcs7::~Pkcs7 (void)
{
}

bool N::Decrypt::Pkcs7::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Decrypt::Pkcs7::type(void) const
{
  return 100022 ;
}

QString N::Decrypt::Pkcs7::name(void)
{
  return QString("RSA") ;
}

QStringList N::Decrypt::Pkcs7::Methods(void)
{
  QStringList E ;
  E << "PKCS"   ;
  E << "OAEP"   ;
  E << "SSLv3"  ;
  E << "RAW"    ;
  return E      ;
}

CUIDs N::Decrypt::Pkcs7::Bits(void)
{
  CUIDs IDs   ;
  IDs <<  512 ;
  IDs << 1024 ;
  IDs << 2048 ;
  IDs << 4096 ;
  return IDs  ;
}

bool N::Decrypt::Pkcs7::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
