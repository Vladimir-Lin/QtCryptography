#include <qtcryptography>
#include <openssl/ocsp.h>

N::Encrypt::Oscp:: Oscp      (void)
                 : Encryptor (    )
{
}

N::Encrypt::Oscp::~Oscp (void)
{
}

bool N::Encrypt::Oscp::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Encrypt::Oscp::type(void) const
{
  return 100020 ;
}

QString N::Encrypt::Oscp::name(void)
{
  return QString("OCSP") ;
}

QStringList N::Encrypt::Oscp::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::Oscp::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::Oscp::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
