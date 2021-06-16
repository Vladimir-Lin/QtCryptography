#include <qtcryptography>
#include <openssl/rc2.h>

N::Decrypt::Rc2:: Rc2       (void)
                : Decryptor (    )
{
}

N::Decrypt::Rc2::~Rc2 (void)
{
}

bool N::Decrypt::Rc2::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Decrypt::Rc2::type(void) const
{
  return 100008 ;
}

QString N::Decrypt::Rc2::name(void)
{
  return QString("RC2") ;
}

QStringList N::Decrypt::Rc2::Methods(void)
{
  QStringList E ;
  E << "CBC"    ;
  E << "ECB"    ;
//  E << "CFB"    ;
//  E << "OFB"    ;
  return E      ;
}

CUIDs N::Decrypt::Rc2::Bits(void)
{
  CUIDs  IDs               ;
  for (int i=1;i<=128;i++) {
    IDs << ( i * 8 )       ;
  }                        ;
  return IDs               ;
}

bool N::Decrypt::Rc2::decrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3)                               {
    if (Key.size()!=288) return false                     ;
    unsigned char * y = (unsigned char *)Key.data()       ;
    char          * z = (char          *)Key.data()       ;
    if (type()!=(((int*)y)[0])) return false              ;
    if (Arguments.count()<1)                              {
      Arguments << ((int          *)y)[5]                 ;
    }                                                     ;
    if (Arguments.count()<2)                              {
      QByteArray S                                        ;
      S.append(z+28,3)                                    ;
      Arguments << QString::fromUtf8(S)                   ;
    }                                                     ;
    if (Arguments.count()<3)                              {
      QByteArray S                                        ;
      S.append(z+32,256)                                  ;
      Arguments << QString::fromUtf8(S)                   ;
    }                                                     ;
    if (Arguments.count()<4)                              {
      Arguments << ((unsigned int *)y)[1]                 ;
    }                                                     ;
    if (Arguments.count()<5)                              {
      Arguments << ((unsigned int *)y)[2]                 ;
    }                                                     ;
    if (Arguments.count()<6)                              {
      Arguments << ((int          *)y)[3]                 ;
    }                                                     ;
    if (Arguments.count()<7)                              {
      Arguments << ((int          *)y)[4]                 ;
    }                                                     ;
  }                                                       ;
  if (Arguments.count()< 3) return false                  ;
  if (input    .size ()<=0) return false                  ;
  /////////////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()                     ;
  if ((bits%8)!=0  ) return false                         ;
  if ((bits/8)<=0  ) return false                         ;
  if ((bits/8)> 128) return false                         ;
  /////////////////////////////////////////////////////////
  QString mode    = Arguments[1].toString()               ;
  bool    correct = false                                 ;
  mode    = mode.toUpper()                                ;
  if (mode=="ECB") correct = true                         ;
  if (mode=="CBC") correct = true                         ;
  if (mode=="CFB") correct = true                         ;
  if (mode=="OFB") correct = true                         ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString       key = Arguments[2].toString()             ;
  unsigned char k[256]                                    ;
  CopyKey ( key , k , 256 )                               ;
  /////////////////////////////////////////////////////////
  RC2_KEY K                                               ;
  unsigned char IV[1024]                                  ;
  memset ( IV , 0 , 1024 )                                ;
  :: RC2_set_key ( &K , key.length() , k , bits )         ;
  /////////////////////////////////////////////////////////
  int              len   = input.size()                   ;
  int              index = 0                              ;
  unsigned char *  d     = (unsigned char *)input.data()  ;
  output . clear ( )                                      ;
  if (mode=="ECB")                                        {
    unsigned char   o[16]                                 ;
    unsigned char   x[16]                                 ;
    while (index<len)                                     {
      int ds = len - index                                ;
      if (ds>8) ds = 8                                    ;
      memset ( o , 0 , 16 )                               ;
      memset ( x , 0 , 16 )                               ;
      memcpy ( x , d , ds )                               ;
      ::RC2_ecb_encrypt ( d , o , &K , RC2_DECRYPT      ) ;
      output . append   ( (const char *)o , 8        )    ;
      d     += 8                                          ;
      index += 8                                          ;
    }                                                     ;
  } else
  if (mode=="CBC")                                        {
    int slen = len                                        ;
    unsigned char * o                                     ;
    if (Arguments.count()>5)                              {
      slen = Arguments[5].toInt()                         ;
    }                                                     ;
    output . resize ( slen )                              ;
    o = (unsigned char *) output . data ( )               ;
    ::RC2_cbc_encrypt ( d,o,len,&K,IV,RC2_DECRYPT       ) ;
  } else
  if (mode=="CFB")                                        {
//      void RC2_cfb64_encrypt(const unsigned char *in, unsigned char *out,long length, RC2_KEY *schedule, unsigned char *ivec,int *num, int enc);
  } else
  if (mode=="OFB")                                        {
//      void RC2_ofb64_encrypt(const unsigned char *in, unsigned char *out,long length, RC2_KEY *schedule, unsigned char *ivec,int *num);
  }                                                       ;
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
  return true ;
}
