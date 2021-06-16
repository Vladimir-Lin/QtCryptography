#include <qtcryptography>
#include <openssl/idea.h>

N::Encrypt::Idea:: Idea      (void)
                 : Encryptor (    )
{
}

N::Encrypt::Idea::~Idea (void)
{
}

bool N::Encrypt::Idea::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Encrypt::Idea::type(void) const
{
  return 100007 ;
}

QString N::Encrypt::Idea::name(void)
{
  return QString("IDEA") ;
}

QStringList N::Encrypt::Idea::Methods(void)
{
  QStringList E ;
  E << "CBC"    ;
  E << "ECB"    ;
  E << "CFB"    ;
  E << "OFB"    ;
  return E      ;
}

CUIDs N::Encrypt::Idea::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::Idea::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
