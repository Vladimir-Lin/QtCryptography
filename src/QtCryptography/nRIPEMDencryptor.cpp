#include <qtcryptography>
#include <openssl/ripemd.h>

N::Encrypt::RipeMd:: RipeMd    (void)
                   : Encryptor (    )
{
}

N::Encrypt::RipeMd::~RipeMd (void)
{
}

bool N::Encrypt::RipeMd::supports (int algorithm)
{
  return ( Cryptography::Digest == algorithm ) ;
}

int N::Encrypt::RipeMd::type(void) const
{
  return 100018 ;
}

QString N::Encrypt::RipeMd::name(void)
{
  return QString("RipeMD") ;
}

QStringList N::Encrypt::RipeMd::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Encrypt::RipeMd::Bits(void)
{
  CUIDs  IDs ;
  IDs << 160 ;
  return IDs ;
}

bool N::Encrypt::RipeMd::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 1) return false              ;
  if (input    .size ()<=0) return false              ;
  /////////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()                 ;
  bool correct = false                                ;
  if (bits==160) correct = true                       ;
  if (!correct) return false                          ;
  /////////////////////////////////////////////////////
  RIPEMD160_CTX   ctx                                 ;
  unsigned char * oup = NULL                          ;
  void          * inp = (void *)input.data()          ;
  int             len = input.size()                  ;
  if (!::RIPEMD160_Init(&ctx)) return false           ;
  output . resize ( RIPEMD160_DIGEST_LENGTH )         ;
  oup    = (unsigned char *)output.data()             ;
  if (!::RIPEMD160_Update(&ctx,inp,len)) return false ;
  if (!::RIPEMD160_Final (oup,&ctx    )) return false ;
  /////////////////////////////////////////////////////
  return true                                         ;
}
