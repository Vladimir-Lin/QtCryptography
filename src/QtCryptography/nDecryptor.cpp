#include <qtcryptography>

N::Decryptor:: Decryptor(void)
{
}

N::Decryptor::~Decryptor(void)
{
}

void N::Decryptor::CopyKey(QString key,unsigned char * k,int length)
{
  QByteArray K = key . toUtf8 ( )  ;
  int        L = K   . size   ( )  ;
  memset ( k , 0 , length )        ;
  if (K.size()<=0) return          ;
  if (L>length) L = length         ;
  memcpy ( k , K.constData() , L ) ;
}

///////////////////////////////////////////////////////////////////////////////

CUIDs N::Decryptors(void)
{
  CUIDs IDs     ;
  IDs << 100001 ;
  IDs << 100002 ;
  IDs << 100003 ;
//  IDs << 100004 ;
  IDs << 100005 ;
  IDs << 100006 ;
//  IDs << 100007 ;
  IDs << 100008 ;
  IDs << 100009 ;
//  IDs << 100010 ;
//  IDs << 100011 ;
//  IDs << 100012 ;
  ///////////////
//  IDs << 100019 ;
//  IDs << 100020 ;
//  IDs << 100021 ;
//  IDs << 100022 ;
//  IDs << 100023 ;
//  IDs << 100024 ;
//  IDs << 100025 ;
  return IDs    ;
}

N::Decryptor * N::decryptor(int type)
{
  switch (type)                    {
    case 100001                    :
    return new Decrypt::Aes     () ;
    case 100002                    :
    return new Decrypt::Des     () ;
    case 100003                    :
    return new Decrypt::Rsa     () ;
    case 100004                    :
    return new Decrypt::Dsa     () ;
    case 100005                    :
    return new Decrypt::Blowfish() ;
    case 100006                    :
    return new Decrypt::Cast    () ;
    case 100007                    :
    return new Decrypt::Idea    () ;
    case 100008                    :
    return new Decrypt::Rc2     () ;
    case 100009                    :
    return new Decrypt::Rc4     () ;
    case 100010                    :
    return new Decrypt::Rc5     () ;
    case 100011                    :
    return new Decrypt::DH      () ;
    case 100012                    :
    return new Decrypt::EC      () ;
    case 100019                    :
    return new Decrypt::Asn1    () ;
    case 100020                    :
    return new Decrypt::Oscp    () ;
    case 100021                    :
    return new Decrypt::Pem     () ;
    case 100022                    :
    return new Decrypt::Pkcs7   () ;
    case 100023                    :
    return new Decrypt::Pkcs12  () ;
    case 100024                    :
    return new Decrypt::x509    () ;
    case 100025                    :
    return new Decrypt::x509v3  () ;
  }                                ;
  return NULL                      ;
}
