#include <qtcryptography>
#include <openssl/dh.h>

N::Decrypt::DH:: DH        (void)
               : Decryptor (    )
{
}

N::Decrypt::DH::~DH (void)
{
}

bool N::Decrypt::DH::supports (int algorithm)
{
  return ( Cryptography::Signature == algorithm ) ;
}

int N::Decrypt::DH::type(void) const
{
  return 100011 ;
}

QString N::Decrypt::DH::name(void)
{
  return QString("DH") ;
}

QStringList N::Decrypt::DH::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::DH::Bits(void)
{
  CUIDs IDs   ;
  return IDs  ;
}

bool N::Decrypt::DH::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
