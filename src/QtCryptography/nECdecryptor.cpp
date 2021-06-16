#include <qtcryptography>
#include <openssl/ec.h>

N::Decrypt::EC:: EC        (void)
               : Decryptor (    )
{
}

N::Decrypt::EC::~EC (void)
{
}

bool N::Decrypt::EC::supports (int algorithm)
{
  return ( Cryptography::Others == algorithm ) ;
}

int N::Decrypt::EC::type(void) const
{
  return 100012 ;
}

QString N::Decrypt::EC::name(void)
{
  return QString("EC") ;
}

QStringList N::Decrypt::EC::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::EC::Bits(void)
{
  CUIDs IDs   ;
  return IDs  ;
}

bool N::Decrypt::EC::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
