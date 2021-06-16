#include <qtcryptography>
#include <openssl/md4.h>

N::Encrypt::Md4:: Md4       (void)
                : Encryptor (    )
{
}

N::Encrypt::Md4::~Md4 (void)
{
}

bool N::Encrypt::Md4::supports (int algorithm)
{
  return ( Cryptography::Digest == algorithm ) ;
}

int N::Encrypt::Md4::type(void) const
{
  return 100014 ;
}

QString N::Encrypt::Md4::name(void)
{
  return QString("MD4") ;
}

QStringList N::Encrypt::Md4::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Encrypt::Md4::Bits(void)
{
  CUIDs  IDs ;
  IDs << 128 ;
  return IDs ;
}

bool N::Encrypt::Md4::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 1) return false        ;
  if (input    .size ()<=0) return false        ;
  ///////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()           ;
  bool correct = false                          ;
  if (bits==128) correct = true                 ;
  if (!correct) return false                    ;
  ///////////////////////////////////////////////
  MD4_CTX         md4                           ;
  unsigned char * oup = NULL                    ;
  void          * inp = (void *)input.data()    ;
  int             len = input.size()            ;
  if (!::MD4_Init(&md4)) return false           ;
  output . resize ( MD4_DIGEST_LENGTH )         ;
  oup    = (unsigned char *)output.data()       ;
  if (!::MD4_Update(&md4,inp,len)) return false ;
  if (!::MD4_Final (oup,&md4    )) return false ;
  ///////////////////////////////////////////////
  return true                                   ;
}
