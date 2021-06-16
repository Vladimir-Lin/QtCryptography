#include <qtcryptography>
#include <openssl/idea.h>

N::Decrypt::Idea:: Idea      (void)
                 : Decryptor (    )
{
}

N::Decrypt::Idea::~Idea (void)
{
}

bool N::Decrypt::Idea::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Decrypt::Idea::type(void) const
{
  return 100007 ;
}

QString N::Decrypt::Idea::name(void)
{
  return QString("IDEA") ;
}

QStringList N::Decrypt::Idea::Methods(void)
{
  QStringList E ;
  E << "CBC"    ;
  E << "ECB"    ;
  E << "CFB"    ;
  E << "OFB"    ;
  return E      ;
}

CUIDs N::Decrypt::Idea::Bits(void)
{
  CUIDs IDs  ;
  return IDs ;
}

bool N::Decrypt::Idea::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
