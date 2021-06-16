#include <qtcryptography>
#include <openssl/ocsp.h>

N::Decrypt::Oscp:: Oscp      (void)
                 : Decryptor (    )
{
}

N::Decrypt::Oscp::~Oscp (void)
{
}

bool N::Decrypt::Oscp::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Decrypt::Oscp::type(void) const
{
  return 100020 ;
}

QString N::Decrypt::Oscp::name(void)
{
  return QString("OCSP") ;
}

QStringList N::Decrypt::Oscp::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::Oscp::Bits(void)
{
  CUIDs IDs  ;
  return IDs ;
}

bool N::Decrypt::Oscp::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
