#include <qtcryptography>
#include <openssl/pkcs7.h>

N::Encrypt::Pkcs7:: Pkcs7     (void)
                  : Encryptor (    )
{
}

N::Encrypt::Pkcs7::~Pkcs7 (void)
{
}

bool N::Encrypt::Pkcs7::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Encrypt::Pkcs7::type(void) const
{
  return 100022 ;
}

QString N::Encrypt::Pkcs7::name(void)
{
  return QString("PKCS7") ;
}

QStringList N::Encrypt::Pkcs7::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::Pkcs7::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::Pkcs7::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
