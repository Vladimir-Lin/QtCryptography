#include <qtcryptography>

// actually , this requires import from crypto++

N::Encrypt::Md2:: Md2       (void)
                : Encryptor (    )
{
}

N::Encrypt::Md2::~Md2 (void)
{
}

bool N::Encrypt::Md2::supports (int algorithm)
{
  return ( Cryptography::Digest == algorithm ) ;
}

int N::Encrypt::Md2::type(void) const
{
  return 100013 ;
}

QString N::Encrypt::Md2::name(void)
{
  return QString("MD2") ;
}

QStringList N::Encrypt::Md2::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::Md2::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::Md2::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
