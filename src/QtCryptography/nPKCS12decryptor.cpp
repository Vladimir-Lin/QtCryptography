#include <qtcryptography>
#include <openssl/pkcs12.h>

N::Decrypt::Pkcs12:: Pkcs12    (void)
                   : Decryptor (    )
{
}

N::Decrypt::Pkcs12::~Pkcs12 (void)
{
}

bool N::Decrypt::Pkcs12::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Decrypt::Pkcs12::type(void) const
{
  return 100023 ;
}

QString N::Decrypt::Pkcs12::name(void)
{
  return QString("PKCS12") ;
}

QStringList N::Decrypt::Pkcs12::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::Pkcs12::Bits(void)
{
  CUIDs IDs   ;
  return IDs  ;
}

bool N::Decrypt::Pkcs12::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
