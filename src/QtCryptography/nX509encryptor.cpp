#include <qtcryptography>
#include <openssl/x509.h>

N::Encrypt::x509:: x509      (void)
                 : Encryptor (    )
{
}

N::Encrypt::x509::~x509 (void)
{
}

bool N::Encrypt::x509::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Encrypt::x509::type(void) const
{
  return 100024 ;
}

QString N::Encrypt::x509::name(void)
{
  return QString("x509") ;
}

QStringList N::Encrypt::x509::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::x509::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::x509::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
