#include <qtcryptography>
#include <openssl/pem.h>

N::Decrypt::Pem:: Pem       (void)
                : Decryptor (    )
{
}

N::Decrypt::Pem::~Pem (void)
{
}

bool N::Decrypt::Pem::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Decrypt::Pem::type(void) const
{
  return 100021 ;
}

QString N::Decrypt::Pem::name(void)
{
  return QString("PEM") ;
}

QStringList N::Decrypt::Pem::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::Pem::Bits(void)
{
  CUIDs IDs  ;
  return IDs ;
}

bool N::Decrypt::Pem::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
