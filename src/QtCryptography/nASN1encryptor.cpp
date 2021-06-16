#include <qtcryptography>
#include <openssl/asn1.h>

N::Encrypt::Asn1:: Asn1      (void)
                 : Encryptor (    )
{
}

N::Encrypt::Asn1::~Asn1 (void)
{
}

bool N::Encrypt::Asn1::supports (int algorithm)
{
  return ( Cryptography::PKI == algorithm ) ;
}

int N::Encrypt::Asn1::type(void) const
{
  return 100019 ;
}

QString N::Encrypt::Asn1::name(void)
{
  return QString("ASN.1") ;
}

QStringList N::Encrypt::Asn1::Methods(void)
{
  QStringList E ;
  return E      ;
}

CUIDs N::Encrypt::Asn1::Bits(void)
{
  CUIDs  IDs  ;
  return IDs  ;
}

bool N::Encrypt::Asn1::encrypt(QByteArray & input,QByteArray & output)
{
  return true ;
}
