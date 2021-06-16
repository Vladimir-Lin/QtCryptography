#include <qtcryptography>
#include <openssl/dsa.h>

N::Decrypt::Dsa:: Dsa       (void)
                : Decryptor (    )
{
}

N::Decrypt::Dsa::~Dsa (void)
{
}

bool N::Decrypt::Dsa::supports (int algorithm)
{
  return ( Cryptography::Signature == algorithm ) ;
}

int N::Decrypt::Dsa::type(void) const
{
  return 100004 ;
}

QString N::Decrypt::Dsa::name(void)
{
  return QString("DSA") ;
}

QStringList N::Decrypt::Dsa::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Decrypt::Dsa::Bits(void)
{
  CUIDs IDs   ;
  IDs <<   64 ;
  IDs <<  128 ;
  IDs <<  256 ;
  IDs <<  384 ;
  IDs <<  512 ;
  IDs <<  768 ;
  IDs << 1024 ;
  IDs << 2048 ;
  IDs << 3072 ;
  IDs << 4096 ;
  return IDs  ;
}

bool N::Decrypt::Dsa::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
