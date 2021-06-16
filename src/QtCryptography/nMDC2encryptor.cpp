#include <qtcryptography>
#include <openssl/mdc2.h>

N::Encrypt::Mdc2:: Mdc2      (void)
                 : Encryptor (    )
{
}

N::Encrypt::Mdc2::~Mdc2 (void)
{
}

bool N::Encrypt::Mdc2::supports (int algorithm)
{
  return ( Cryptography::Digest == algorithm ) ;
}

int N::Encrypt::Mdc2::type(void) const
{
  return 100016 ;
}

QString N::Encrypt::Mdc2::name(void)
{
  return QString("MDC2") ;
}

QStringList N::Encrypt::Mdc2::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Encrypt::Mdc2::Bits(void)
{
  CUIDs  IDs ;
  IDs << 128 ;
  return IDs ;
}

bool N::Encrypt::Mdc2::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 1) return false          ;
  if (input    .size ()<=0) return false          ;
  /////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()             ;
  bool correct = false                            ;
  if (bits==128) correct = true                   ;
  if (!correct) return false                      ;
  /////////////////////////////////////////////////
  MDC2_CTX        mdc2                            ;
  unsigned char * oup = NULL                      ;
  unsigned char * inp = NULL                      ;
  int             len = input.size()              ;
  if (!::MDC2_Init(&mdc2)) return false           ;
  output . resize ( MDC2_DIGEST_LENGTH )          ;
  oup    = (unsigned char *)output.data()         ;
  inp    = (unsigned char *)input .data()         ;
  if (!::MDC2_Update(&mdc2,inp,len)) return false ;
  if (!::MDC2_Final (oup,&mdc2    )) return false ;
  /////////////////////////////////////////////////
  return true                                     ;
}
