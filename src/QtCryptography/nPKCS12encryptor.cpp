#include <qtcryptography>
#include <openssl/pkcs12.h>

N::Encrypt::Pkcs12:: Pkcs12    (void)
                   : Encryptor (    )
{
}

N::Encrypt::Pkcs12::~Pkcs12 (void)
{
}

bool N::Encrypt::Pkcs12::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Encrypt::Pkcs12::type(void) const
{
  return 100023 ;
}

QString N::Encrypt::Pkcs12::name(void)
{
  return QString("PKCS12") ;
}

QStringList N::Encrypt::Pkcs12::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::Pkcs12::Bits(void)
{
  CUIDs  IDs ;
  return IDs ;
}

bool N::Encrypt::Pkcs12::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
