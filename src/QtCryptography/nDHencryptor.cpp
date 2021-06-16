#include <qtcryptography>
#include <openssl/dh.h>

N::Encrypt::DH:: DH        (void)
               : Encryptor (    )
{
}

N::Encrypt::DH::~DH (void)
{
}

bool N::Encrypt::DH::supports (int algorithm)
{
  return ( Cryptography::Signature == algorithm ) ;
}

int N::Encrypt::DH::type(void) const
{
  return 100011 ;
}

QString N::Encrypt::DH::name(void)
{
  return QString("DH") ;
}

QStringList N::Encrypt::DH::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::DH::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::DH::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
