#include <qtcryptography>
#include <openssl/x509v3.h>

N::Encrypt::x509v3:: x509v3    (void)
                   : Encryptor (    )
{
}

N::Encrypt::x509v3::~x509v3 (void)
{
}

bool N::Encrypt::x509v3::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Encrypt::x509v3::type(void) const
{
  return 100025 ;
}

QString N::Encrypt::x509v3::name(void)
{
  return QString("x509v3") ;
}

QStringList N::Encrypt::x509v3::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::x509v3::Bits(void)
{
  CUIDs  IDs ;
  return IDs ;
}

bool N::Encrypt::x509v3::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
