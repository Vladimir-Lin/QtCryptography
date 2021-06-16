#include <qtcryptography>

// actually , this requires import from crypto++

N::Decrypt::Rc5:: Rc5       (void)
                : Decryptor (    )
{
}

N::Decrypt::Rc5::~Rc5 (void)
{
}

bool N::Decrypt::Rc5::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Decrypt::Rc5::type(void) const
{
  return 100010 ;
}

QString N::Decrypt::Rc5::name(void)
{
  return QString("RC5") ;
}

QStringList N::Decrypt::Rc5::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::Rc5::Bits(void)
{
  CUIDs IDs  ;
  return IDs ;
}

bool N::Decrypt::Rc5::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
