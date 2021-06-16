#include <qtcryptography>
#include <openssl/x509v3.h>

N::Decrypt::x509v3:: x509v3    (void)
                   : Decryptor (    )
{
}

N::Decrypt::x509v3::~x509v3 (void)
{
}

bool N::Decrypt::x509v3::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Decrypt::x509v3::type(void) const
{
  return 100025 ;
}

QString N::Decrypt::x509v3::name(void)
{
  return QString("x509v3") ;
}

QStringList N::Decrypt::x509v3::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::x509v3::Bits(void)
{
  CUIDs IDs  ;
  return IDs ;
}

bool N::Decrypt::x509v3::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
