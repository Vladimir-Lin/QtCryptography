#include <qtcryptography>
#include <openssl/x509.h>

N::Decrypt::x509:: x509      (void)
                 : Decryptor (    )
{
}

N::Decrypt::x509::~x509 (void)
{
}

bool N::Decrypt::x509::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Decrypt::x509::type(void) const
{
  return 100024 ;
}

QString N::Decrypt::x509::name(void)
{
  return QString("x509") ;
}

QStringList N::Decrypt::x509::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::x509::Bits(void)
{
  CUIDs IDs  ;
  return IDs ;
}

bool N::Decrypt::x509::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
