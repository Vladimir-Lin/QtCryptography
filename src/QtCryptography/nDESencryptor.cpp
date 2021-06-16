#include <qtcryptography>
#include <openssl/des.h>

N::Encrypt::Des:: Des       (void)
                : Encryptor (    )
{
}

N::Encrypt::Des::~Des (void)
{
}

bool N::Encrypt::Des::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Encrypt::Des::type(void) const
{
  return 100002 ;
}

QString N::Encrypt::Des::name(void)
{
  return QString("DES") ;
}

QStringList N::Encrypt::Des::Methods(void)
{
  QStringList E    ;
  E << "CBC"       ;
  E << "ECB"       ;
//  E << "CFB"       ;
//  E << "OFB"       ;
//  E << "3-DES CBC" ;
//  E << "3-DES ECB" ;
  return E         ;
}

CUIDs N::Encrypt::Des::Bits(void)
{
  CUIDs  IDs ;
  IDs << 64  ;
  return IDs ;
}

bool N::Encrypt::Des::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3) return false                  ;
  if (input    .size ()<=0) return false                  ;
  /////////////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()                     ;
  bool correct = false                                    ;
  if (bits==64) correct = true                            ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString mode = Arguments[1].toString()                  ;
  mode    = mode.toUpper()                                ;
  correct = false                                         ;
  if (mode=="CBC"      ) correct = true                   ;
  if (mode=="ECB"      ) correct = true                   ;
  if (mode=="3-DES CBC") correct = true                   ;
  if (mode=="3-DES ECB") correct = true                   ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString       key = Arguments[2].toString()             ;
  unsigned char k[32]                                     ;
  CopyKey ( key , k , 32 )                                ;
  /////////////////////////////////////////////////////////
  DES_cblock       K1                                     ;
  DES_cblock       K2                                     ;
  DES_cblock       K3                                     ;
  DES_key_schedule S1                                     ;
  DES_key_schedule S2                                     ;
  DES_key_schedule S3                                     ;
  if ( mode == "CBC"       || mode == "ECB"       )       {
    memcpy                  (  K1 , k     , 8 )           ;
    ::DES_set_key_unchecked ( &K1 , &S1       )           ;
  } else
  if ( mode == "3-DES CBC" || mode == "3-DES ECB" )       {
    memcpy                  (  K1 , k      , 8 )          ;
    ::DES_set_key_unchecked ( &K1 , &S1        )          ;
    memcpy                  (  K2 , k +  8 , 8 )          ;
    ::DES_set_key_unchecked ( &K2 , &S2        )          ;
    memcpy                  (  K3 , k      , 8 )          ;
    ::DES_set_key_unchecked ( &K3 , &S3        )          ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  const_DES_cblock INPT                                   ;
  DES_cblock       OUTP                                   ;
  DES_cblock       IVEC                                   ;
  int              len   = input.size()                   ;
  int              index = 0                              ;
  unsigned char * d     = (unsigned char *)input.data()   ;
  output . clear ( )                                      ;
  memset ( &IVEC , 0 , sizeof(DES_cblock) )               ;
  memset ( &OUTP , 0 , sizeof(DES_cblock) )               ;
  if (mode=="ECB")                                        {
    unsigned char   o[16]                                 ;
    unsigned char   x[16]                                 ;
    while (index<len)                                     {
      int ds = len - index                                ;
      if (ds>8) ds = 8                                    ;
      memset ( o , 0 , 16 )                               ;
      memset ( x , 0 , 16 )                               ;
      memcpy ( x , d , ds )                               ;
      memcpy            ( INPT ,x    ,8                 ) ;
      ::DES_ecb_encrypt ( &INPT,&OUTP,&S1,DES_ENCRYPT   ) ;
      memcpy            ( o    ,OUTP ,8                 ) ;
      output . append   ( (const char *)o , 8           ) ;
      d     += 8                                          ;
      index += 8                                          ;
    }                                                     ;
  } else
  if (mode=="CBC")                                        {
    unsigned char * o                                     ;
    output . resize ( len )                               ;
    o = (unsigned char *) output . data ( )               ;
    ::DES_ncbc_encrypt( d,o,len,&S1,&IVEC,DES_ENCRYPT   ) ;
  } else
  if (mode=="3-DES ECB")                                  {
    unsigned char   o[16]                                 ;
    unsigned char   x[16]                                 ;
    while (index<len)                                     {
      int ds = len - index                                ;
      if (ds>8) ds = 8                                    ;
      memset ( o , 0 , 16 )                               ;
      memset ( x , 0 , 16 )                               ;
      memcpy ( x , d , ds )                               ;
      memcpy            ( INPT ,x    ,8                 ) ;
      ::DES_ecb3_encrypt( &INPT                           ,
                          &OUTP                           ,
                          &S1                             ,
                          &S2                             ,
                          &S3                             ,
                          DES_ENCRYPT                   ) ;
      memcpy            ( o    ,OUTP ,8                 ) ;
      output . append   ( (const char *)o , 8           ) ;
      d     += 8                                          ;
      index += 8                                          ;
    }                                                     ;
  } else
  if (mode=="3-DES CBC")                                  {
    unsigned char * o                                     ;
    output . resize ( len )                               ;
    o = (unsigned char *) output . data ( )               ;
    ::DES_ede3_cbc_encrypt ( d                            ,
                             o                            ,
                             len                          ,
                             &S1                          ,
                             &S2                          ,
                             &S3                          ,
                             &IVEC                        ,
                             DES_ENCRYPT                ) ;
  }                                                       ;
  if (output.size()<=0) return false                      ;
  /////////////////////////////////////////////////////////
  Key . resize ( 96 )                                     ;
  unsigned char * y = (unsigned char *)Key.data()         ;
  char          * z = (char          *)Key.data()         ;
  memset ( y , 0 , 96 )                                   ;
  ((int          *)y)[0] = type    (            )         ;
  ((unsigned int *)y)[1] = ADLER32 ( input  , 0 )         ;
  ((unsigned int *)y)[2] = ADLER32 ( output , 0 )         ;
  ((int          *)y)[3] = input  . size ( )              ;
  ((int          *)y)[4] = output . size ( )              ;
  ((int          *)y)[5] = bits                           ;
  strcpy ( z + 32 , mode.toUtf8().constData() )           ;
  memcpy ( z + 64 , k , 32                    )           ;
  /////////////////////////////////////////////////////////
  return true                                             ;
}
