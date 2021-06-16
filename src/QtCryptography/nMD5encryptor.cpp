#include <qtcryptography>
#include <openssl/md5.h>

N::Encrypt::Md5:: Md5       (void)
                : Encryptor (    )
{
}

N::Encrypt::Md5::~Md5 (void)
{
}

bool N::Encrypt::Md5::supports (int algorithm)
{
  return ( Cryptography::Digest == algorithm ) ;
}

int N::Encrypt::Md5::type(void) const
{
  return 100015 ;
}

QString N::Encrypt::Md5::name(void)
{
  return QString("MD5") ;
}

QStringList N::Encrypt::Md5::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Encrypt::Md5::Bits(void)
{
  CUIDs  IDs ;
  IDs << 128 ;
  return IDs ;
}

bool N::Encrypt::Md5::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 1) return false        ;
  if (input    .size ()<=0) return false        ;
  ///////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()           ;
  bool correct = false                          ;
  if (bits==128) correct = true                 ;
  if (!correct) return false                    ;
  ///////////////////////////////////////////////
  MD5_CTX         md5                           ;
  unsigned char * oup = NULL                    ;
  void          * inp = (void *)input.data()    ;
  int             len = input.size()            ;
  if (!::MD5_Init(&md5)) return false           ;
  output . resize ( MD5_DIGEST_LENGTH )         ;
  oup    = (unsigned char *)output.data()       ;
  if (!::MD5_Update(&md5,inp,len)) return false ;
  if (!::MD5_Final (oup,&md5    )) return false ;
  ///////////////////////////////////////////////
  return true                                   ;
}
