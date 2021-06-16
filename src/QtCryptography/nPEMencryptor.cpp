#include <qtcryptography>
#include <openssl/pem.h>

N::Encrypt::Pem:: Pem       (void)
                : Encryptor (    )
{
}

N::Encrypt::Pem::~Pem (void)
{
}

bool N::Encrypt::Pem::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Encrypt::Pem::type(void) const
{
  return 100021 ;
}

QString N::Encrypt::Pem::name(void)
{
  return QString("PEM") ;
}

QStringList N::Encrypt::Pem::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::Pem::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::Pem::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
