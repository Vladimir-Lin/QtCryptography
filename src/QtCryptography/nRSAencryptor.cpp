#include <qtcryptography>
#include <openssl/pem.h>
#include <openssl/rsa.h>

N::Encrypt::Rsa:: Rsa       (void)
                : Encryptor (    )
{
}

N::Encrypt::Rsa::~Rsa (void)
{
}

bool N::Encrypt::Rsa::supports (int algorithm)
{
  return ( Cryptography::Asymmetric == algorithm ) ;
}

int N::Encrypt::Rsa::type(void) const
{
  return 100003 ;
}

QString N::Encrypt::Rsa::name(void)
{
  return QString("RSA") ;
}

QStringList N::Encrypt::Rsa::Methods(void)
{
  QStringList E ;
  E << "PKCS"   ;
  E << "OAEP"   ;
  E << "SSLv3"  ;
  E << "X931"   ;
  E << "RAW"    ;
  return E      ;
}

CUIDs N::Encrypt::Rsa::Bits(void)
{
  CUIDs  IDs  ;
  IDs <<  512 ;
  IDs << 1024 ;
  IDs << 2048 ;
  IDs << 4096 ;
  return IDs  ;
}

bool N::Encrypt::Rsa::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3) return false                  ;
  if (input    .size ()<=0) return false                  ;
  /////////////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()                     ;
  bool correct = false                                    ;
  if ( bits ==  512 ) correct = true                      ;
  if ( bits == 1024 ) correct = true                      ;
  if ( bits == 2048 ) correct = true                      ;
  if ( bits == 4096 ) correct = true                      ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString mode    = Arguments[1].toString()               ;
  int     padding = 0                                     ;
  int     diff    = 0                                     ;
  mode    = mode.toUpper()                                ;
  correct = false                                         ;
  if (mode=="PKCS"  )                                     {
    correct = true                                        ;
    padding = RSA_PKCS1_PADDING                           ;
    diff    = RSA_PKCS1_PADDING_SIZE                      ;
  }                                                       ;
  if (mode=="OAEP"  )                                     {
    correct = true                                        ;
    padding = RSA_PKCS1_OAEP_PADDING                      ;
    diff    = 2 * SHA_DIGEST_LENGTH + 2                   ;
  }                                                       ;
  if (mode=="SSLV23")                                     {
    correct = true                                        ;
    padding = RSA_SSLV23_PADDING                          ;
    diff    = 11                                          ;
  }                                                       ;
  if (mode=="X931"  )                                     {
    correct = true                                        ;
    padding = RSA_X931_PADDING                            ;
    diff    = 2                                           ;
  }                                                       ;
  if (mode=="RAW"   )                                     {
    correct = true                                        ;
    padding = RSA_NO_PADDING                              ;
    diff    = 0                                           ;
  }                                                       ;
  if (!correct) return false                              ;
  if ( 0 == padding ) return false                        ;
  /////////////////////////////////////////////////////////
  RSA    * rsa = RSA_new()                                ;
  BIGNUM * bne = BN_new()                                 ;
  ::BN_set_word ( bne      , RSA_F4 )                     ;
  if ( 1 != ::RSA_generate_key_ex(rsa,bits,bne,NULL) )    {
    ::BN_free ( bne )                                     ;
    return false                                          ;
  }                                                       ;
  ::BN_free ( bne )                                       ;
  /////////////////////////////////////////////////////////
  int             mbs = ::RSA_size(rsa)                   ;
  unsigned char * dat = NULL                              ;
  unsigned char * inp = new unsigned char [mbs]           ;
  unsigned char * oup = new unsigned char [mbs]           ;
  int             enc = 0                                 ;
  mbs -= diff                                             ;
  dat  = (unsigned char *)input.data()                    ;
  while (enc<input.size())                                {
    int ret                                               ;
    int rest = input.size() - enc                         ;
    if (rest>mbs) rest = mbs                              ;
    memset ( inp , 0   , mbs  )                           ;
    memset ( oup , 0   , mbs  )                           ;
    memcpy ( inp , dat , rest )                           ;
    ret = ::RSA_public_encrypt(mbs,inp,oup,rsa,padding)   ;
    if (ret<0)                                            {
      return false                                        ;
    }                                                     ;
    output . append ( (const char *)oup , ret )           ;
    dat += rest                                           ;
    enc += rest                                           ;
  }                                                       ;
  delete [] inp                                           ;
  delete [] oup                                           ;
  if (output.size()<=0) return false                      ;
  /////////////////////////////////////////////////////////
  QByteArray HD                                           ;
  QByteArray PK                                           ;
  QByteArray PI                                           ;
  BIO      * pri = ::BIO_new(::BIO_s_mem())               ;
  BIO      * pub = ::BIO_new(::BIO_s_mem())               ;
  ::PEM_write_bio_RSAPrivateKey                           (
    pri                                                   ,
    rsa                                                   ,
    NULL                                                  ,
    NULL                                                  ,
    0                                                     ,
    NULL                                                  ,
    NULL                                                ) ;
  ::PEM_write_bio_RSAPublicKey ( pub , rsa )              ;
  /////////////////////////////////////////////////////////
  int publen = BIO_pending(pub)                           ;
  int prilen = BIO_pending(pri)                           ;
  PK  . resize ( publen )                                 ;
  PI  . resize ( prilen )                                 ;
  char * pubdat = (char *)PK.data()                       ;
  char * pridat = (char *)PI.data()                       ;
  ::BIO_read ( pub , pubdat, publen )                     ;
  ::BIO_read ( pri , pridat, prilen )                     ;
  /////////////////////////////////////////////////////////
  HD . resize ( 64 )                                      ;
  unsigned char * y = (unsigned char *)HD.data()          ;
  char          * z = (char          *)HD.data()          ;
  memset ( y , 0 , 64 )                                   ;
  ((int          *)y)[0] = type    (            )         ;
  ((unsigned int *)y)[1] = ADLER32 ( input  , 0 )         ;
  ((unsigned int *)y)[2] = ADLER32 ( output , 0 )         ;
  ((int          *)y)[3] = input  . size ( )              ;
  ((int          *)y)[4] = output . size ( )              ;
  ((int          *)y)[5] = bits                           ;
  ((int          *)y)[6] = PI.size()                      ;
  strcpy ( z + 48 , mode.toUtf8().constData() )           ;
  /////////////////////////////////////////////////////////
  Key . clear ( )                                         ;
  Key . append ( HD )                                     ;
  Key . append ( PI )                                     ;
  /////////////////////////////////////////////////////////
  ::RSA_free ( rsa )                                      ;
  ::BIO_free ( pri )                                      ;
  ::BIO_free ( pub )                                      ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
