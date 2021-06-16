#include <qtcryptography>
#include <openssl/sha.h>

N::Encrypt::Sha:: Sha       (void)
                : Encryptor (    )
{
}

N::Encrypt::Sha::~Sha (void)
{
}

bool N::Encrypt::Sha::supports (int algorithm)
{
  return ( Cryptography::Digest == algorithm ) ;
}

int N::Encrypt::Sha::type(void) const
{
  return 100017 ;
}

QString N::Encrypt::Sha::name(void)
{
  return QString("SHA") ;
}

QStringList N::Encrypt::Sha::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Encrypt::Sha::Bits(void)
{
  CUIDs  IDs ;
  IDs << 224 ;
  IDs << 256 ;
  IDs << 384 ;
  IDs << 512 ;
  return IDs ;
}

bool N::Encrypt::Sha::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 1) return false                  ;
  if (input    .size ()<=0) return false                  ;
  /////////////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()                     ;
  bool correct = false                                    ;
  if (bits==224) correct = true                           ;
  if (bits==256) correct = true                           ;
  if (bits==384) correct = true                           ;
  if (bits==512) correct = true                           ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  SHA256_CTX      ctx256                                  ;
  SHA512_CTX      ctx512                                  ;
  unsigned char * oup    = NULL                           ;
  void          * inp    = (void *)input.data()           ;
  int             len    = input.size()                   ;
  switch ( bits )                                         {
    case 224                                              :
      if (!::SHA224_Init(&ctx256)) return false           ;
      output . resize ( SHA224_DIGEST_LENGTH )            ;
      oup    = (unsigned char *)output.data()             ;
      if (!::SHA224_Update(&ctx256,inp,len)) return false ;
      if (!::SHA224_Final (oup,&ctx256    )) return false ;
    break                                                 ;
    case 256                                              :
      if (!::SHA256_Init(&ctx256)) return false           ;
      output . resize ( SHA256_DIGEST_LENGTH )            ;
      oup    = (unsigned char *)output.data()             ;
      if (!::SHA256_Update(&ctx256,inp,len)) return false ;
      if (!::SHA256_Final (oup,&ctx256    )) return false ;
    break                                                 ;
    case 384                                              :
      if (!::SHA384_Init(&ctx512)) return false           ;
      output . resize ( SHA384_DIGEST_LENGTH )            ;
      oup    = (unsigned char *)output.data()             ;
      if (!::SHA384_Update(&ctx512,inp,len)) return false ;
      if (!::SHA384_Final (oup,&ctx512    )) return false ;
    break                                                 ;
    case 512                                              :
      if (!::SHA512_Init(&ctx512)) return false           ;
      output . resize ( SHA512_DIGEST_LENGTH )            ;
      oup    = (unsigned char *)output.data()             ;
      if (!::SHA384_Update(&ctx512,inp,len)) return false ;
      if (!::SHA512_Final (oup,&ctx512    )) return false ;
    break                                                 ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
