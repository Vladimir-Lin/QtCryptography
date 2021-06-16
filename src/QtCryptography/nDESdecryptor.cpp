#include <qtcryptography>
#include <openssl/des.h>

N::Decrypt::Des:: Des       (void)
                : Decryptor (    )
{
}

N::Decrypt::Des::~Des (void)
{
}

bool N::Decrypt::Des::supports (int algorithm)
{
  return ( Cryptography::Cipher == algorithm ) ;
}

int N::Decrypt::Des::type(void) const
{
  return 100002 ;
}

QString N::Decrypt::Des::name(void)
{
  return QString("DES") ;
}

QStringList N::Decrypt::Des::Methods(void)
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

CUIDs N::Decrypt::Des::Bits(void)
{
  CUIDs IDs  ;
  IDs << 64  ;
  return IDs ;
}

bool N::Decrypt::Des::decrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3)                               {
    if (Key.size()!=96) return false                      ;
    unsigned char * y = (unsigned char *)Key.data()       ;
    char          * z = (char          *)Key.data()       ;
    if (type()!=(((int*)y)[0])) return false              ;
    if (Arguments.count()<1)                              {
      Arguments << ((int          *)y)[5]                 ;
    }                                                     ;
    if (Arguments.count()<2)                              {
      QByteArray S                                        ;
      S.append(z+32,16)                                   ;
      if (S.indexOf("3-DES"))                             {
        S.resize(9)                                       ;
      } else                                              {
        S.resize(3)                                       ;
      }                                                   ;
      Arguments << QString::fromUtf8(S)                   ;
    }                                                     ;
    if (Arguments.count()<3)                              {
      QByteArray S                                        ;
      S.append(z+64,32)                                   ;
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
    memcpy                  ( K1 , k      , 8 )           ;
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
  unsigned char *  d     = (unsigned char *)input.data()  ;
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
      ::DES_ecb_encrypt ( &INPT,&OUTP,&S1,DES_DECRYPT   ) ;
      memcpy            ( o    ,OUTP ,8                 ) ;
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
    ::DES_ncbc_encrypt( d,o,slen,&S1,&IVEC,DES_DECRYPT  ) ;
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
                          DES_DECRYPT                   ) ;
      memcpy            ( o    ,OUTP ,8                 ) ;
      output . append   ( (const char *)o , 8           ) ;
      d     += 8                                          ;
      index += 8                                          ;
    }                                                     ;
  } else
  if (mode=="3-DES CBC")                                  {
    int slen = len                                        ;
    unsigned char * o                                     ;
    if (Arguments.count()>5)                              {
      slen = Arguments[5].toInt()                         ;
    }                                                     ;
    output . resize ( slen )                              ;
    o = (unsigned char *) output . data ( )               ;
    ::DES_ede3_cbc_encrypt ( d                            ,
                             o                            ,
                             slen                         ,
                             &S1                          ,
                             &S2                          ,
                             &S3                          ,
                             &IVEC                        ,
                             DES_DECRYPT                ) ;
  }                                                       ;
  if (output.size()<=0) return false                      ;
  /////////////////////////////////////////////////////////
  if (Arguments.count()>5)                                {
    int ics = Arguments[5].toInt()                        ;
    if ( output.size() != ics ) output . resize ( ics )   ;
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
