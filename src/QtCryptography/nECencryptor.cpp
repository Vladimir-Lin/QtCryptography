#include <qtcryptography>
#include <openssl/ec.h>

N::Encrypt::EC:: EC        (void)
               : Encryptor (    )
{
}

N::Encrypt::EC::~EC (void)
{
}

bool N::Encrypt::EC::supports (int algorithm)
{
  return ( Cryptography::Others == algorithm ) ;
}

int N::Encrypt::EC::type(void) const
{
  return 100012 ;
}

QString N::Encrypt::EC::name(void)
{
  return QString("EC") ;
}

QStringList N::Encrypt::EC::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::EC::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::EC::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
