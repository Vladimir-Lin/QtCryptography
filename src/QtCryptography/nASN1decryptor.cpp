#include <qtcryptography>
#include <openssl/asn1.h>

N::Decrypt::Asn1:: Asn1      (void)
                 : Decryptor (    )
{
}

N::Decrypt::Asn1::~Asn1 (void)
{
}

bool N::Decrypt::Asn1::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Decrypt::Asn1::type(void) const
{
  return 100019 ;
}

QString N::Decrypt::Asn1::name(void)
{
  return QString("ASN.1") ;
}

QStringList N::Decrypt::Asn1::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Decrypt::Asn1::Bits(void)
{
  CUIDs IDs   ;
  return IDs  ;
}

bool N::Decrypt::Asn1::decrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
