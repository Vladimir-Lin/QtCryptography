#include <qtcryptography>
#include <openssl/pem.h>
#include <openssl/rsa.h>

N::Decrypt::Rsa:: Rsa       (void)
                : Decryptor (    )
{
}

N::Decrypt::Rsa::~Rsa (void)
{
}

bool N::Decrypt::Rsa::supports (int algorithm)
{
  return ( Cryptography::Asymmetric == algorithm ) ;
}

int N::Decrypt::Rsa::type(void) const
{
  return 100003 ;
}

QString N::Decrypt::Rsa::name(void)
{
  return QString("RSA") ;
}

QStringList N::Decrypt::Rsa::Methods(void)
{
  QStringList E ;
  E << "PKCS"   ;
  E << "OAEP"   ;
  E << "SSLv3"  ;
  E << "X931"   ;
  E << "RAW"    ;
  return E      ;
}

CUIDs N::Decrypt::Rsa::Bits(void)
{
  CUIDs IDs   ;
  IDs <<  512 ;
  IDs << 1024 ;
  IDs << 2048 ;
  IDs << 4096 ;
  return IDs  ;
}

bool N::Decrypt::Rsa::decrypt(QByteArray & input,QByteArray & output)
{
  if (Key.size()<=0) return false                         ;
  QByteArray      PI                                      ;
  unsigned char * y = (unsigned char *)Key.data()         ;
  char          * z = (char          *)Key.data()         ;
  char            K[1024]                                 ;
  int             KL = 0                                  ;
  memset ( K , 0 , 1024 )                                 ;
  if (type()!=(((int*)y)[0])) return false                ;
  Arguments << ((int          *)y)[5]                     ;
  memcpy ( K , z+48 , 16 )                                ;
  QByteArray S ( K )                                      ;
  Arguments << QString::fromUtf8(S)                       ;
  Arguments << ""                                         ;
  Arguments << ((unsigned int *)y)[1]                     ;
  Arguments << ((unsigned int *)y)[2]                     ;
  Arguments << ((int          *)y)[3]                     ;
  Arguments << ((int          *)y)[4]                     ;
  KL = ((int *)y)[6]                                      ;
  PI . append ( z + 64 , KL )                             ;
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
  mode    = mode.toUpper()                                ;
  correct = false                                         ;
  if (mode=="PKCS"  )                                     {
    correct = true                                        ;
    padding = RSA_PKCS1_PADDING                           ;
  }                                                       ;
  if (mode=="OAEP"  )                                     {
    correct = true                                        ;
    padding = RSA_PKCS1_OAEP_PADDING                      ;
  }                                                       ;
  if (mode=="SSLV23")                                     {
    correct = true                                        ;
    padding = RSA_SSLV23_PADDING                          ;
  }                                                       ;
  if (mode=="X931"  )                                     {
    correct = true                                        ;
    padding = RSA_X931_PADDING                            ;
  }                                                       ;
  if (mode=="RAW"   )                                     {
    correct = true                                        ;
    padding = RSA_NO_PADDING                              ;
  }                                                       ;
  if (!correct) return false                              ;
  if ( 0 == padding ) return false                        ;
  /////////////////////////////////////////////////////////
  RSA * rsa = NULL                                        ;
  BIO * bio = ::BIO_new_mem_buf((void *)PI.data(),KL)     ;
  rsa = ::PEM_read_bio_RSAPrivateKey(bio,&rsa,NULL,NULL)  ;
  if (IsNull(rsa)) return false                           ;
  /////////////////////////////////////////////////////////
  int             mbs = ::RSA_size(rsa)                   ;
  unsigned char * inp = new unsigned char [mbs]           ;
  unsigned char * oup = new unsigned char [mbs]           ;
  int             enc = 0                                 ;
  unsigned char * d = (unsigned char *) input  . data ( ) ;
  /////////////////////////////////////////////////////////
  output . clear ( )                                      ;
  while (enc<input.size())                                {
    int ret                                               ;
    int rest = input.size() - enc                         ;
    if (rest>mbs) rest = mbs                              ;
    memset ( inp , 0 , mbs  )                             ;
    memset ( oup , 0 , mbs  )                             ;
    memcpy ( inp , d , rest )                             ;
    ret = ::RSA_private_decrypt(mbs,inp,oup,rsa,padding)  ;
    if (ret<0) return false                               ;
    output . append ( (const char *)oup , ret )           ;
    d   += rest                                           ;
    enc += rest                                           ;
  }                                                       ;
  delete [] inp                                           ;
  delete [] oup                                           ;
  ::BIO_free ( bio )                                      ;
  ::RSA_free ( rsa )                                      ;
  if ( output . size ( ) <= 0 ) return false              ;
  /////////////////////////////////////////////////////////
  if (Arguments.count()>5)                                {
    int ics = Arguments[5].toInt()                        ;
    output . resize ( ics )                               ;
  }                                                       ;
  if (Arguments.count()>6)                                {
    int ics = Arguments[6].toInt()                        ;
    if (ics!=input.size()) return false                   ;
  }                                                       ;
  if (Arguments.count()>3)                                {
    unsigned int ics = Arguments[3].toUInt()              ;
    unsigned int ocs = ADLER32(output,0)                  ;
    if (ics!=ocs) return false                            ;
  }                                                       ;
  if (Arguments.count()>4)                                {
    unsigned int ics = Arguments[4].toUInt()              ;
    unsigned int ocs = ADLER32(input ,0)                  ;
    if (ics!=ocs) return false                            ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
