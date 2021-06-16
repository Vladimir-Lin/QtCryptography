#include <qtcryptography>

// actually , this requires import from crypto++

N::Encrypt::Rc5:: Rc5       (void)
                : Encryptor (    )
{
}

N::Encrypt::Rc5::~Rc5 (void)
{
}

bool N::Encrypt::Rc5::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Encrypt::Rc5::type(void) const
{
  return 100010 ;
}

QString N::Encrypt::Rc5::name(void)
{
  return QString("RC5") ;
}

QStringList N::Encrypt::Rc5::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::Rc5::Bits(void)
{
  CUIDs  IDs ;
  return IDs ;
}

bool N::Encrypt::Rc5::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
