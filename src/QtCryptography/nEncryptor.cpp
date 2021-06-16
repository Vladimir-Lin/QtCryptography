#include <qtcryptography>

N::Encryptor:: Encryptor(void)
{
}

N::Encryptor::~Encryptor(void)
{
}

QString N::Encryptor::PickKey(QString source,int length)
{
  int     L = source.length()        ;
  QString K                          ;
  if (L<=0) return K                 ;
  for (int i=0;i<length;i++)         {
    int n = rand() % L               ;
    K . append ( source . at ( n ) ) ;
  }                                  ;
  return K                           ;
}

void N::Encryptor::CopyKey(QString key,unsigned char * k,int length)
{
  QByteArray K = key . toUtf8 ( )  ;
  int        L = K   . size   ( )  ;
  memset ( k , 0 , length )        ;
  if (K.size()<=0) return          ;
  if (L>length) L = length         ;
  memcpy ( k , K.constData() , L ) ;
}

///////////////////////////////////////////////////////////////////////////////

CUIDs N::Encryptors(void)
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
  IDs << 100013 ;
  IDs << 100014 ;
  IDs << 100015 ;
  IDs << 100016 ;
  IDs << 100017 ;
  IDs << 100018 ;
//  IDs << 100019 ;
//  IDs << 100020 ;
//  IDs << 100021 ;
//  IDs << 100022 ;
//  IDs << 100023 ;
//  IDs << 100024 ;
//  IDs << 100025 ;
  return IDs    ;
}

N::Encryptor * N::encryptor(int type)
{
  switch (type)                    {
    case 100001                    :
    return new Encrypt::Aes     () ;
    case 100002                    :
    return new Encrypt::Des     () ;
    case 100003                    :
    return new Encrypt::Rsa     () ;
    case 100004                    :
    return new Encrypt::Dsa     () ;
    case 100005                    :
    return new Encrypt::Blowfish() ;
    case 100006                    :
    return new Encrypt::Cast    () ;
    case 100007                    :
    return new Encrypt::Idea    () ;
    case 100008                    :
    return new Encrypt::Rc2     () ;
    case 100009                    :
    return new Encrypt::Rc4     () ;
    case 100010                    :
    return new Encrypt::Rc5     () ;
    case 100011                    :
    return new Encrypt::DH      () ;
    case 100012                    :
    return new Encrypt::EC      () ;
    case 100013                    :
    return new Encrypt::Md2     () ;
    case 100014                    :
    return new Encrypt::Md4     () ;
    case 100015                    :
    return new Encrypt::Md5     () ;
    case 100016                    :
    return new Encrypt::Mdc2    () ;
    case 100017                    :
    return new Encrypt::Sha     () ;
    case 100018                    :
    return new Encrypt::RipeMd  () ;
    case 100019                    :
    return new Encrypt::Asn1    () ;
    case 100020                    :
    return new Encrypt::Oscp    () ;
    case 100021                    :
    return new Encrypt::Pem     () ;
    case 100022                    :
    return new Encrypt::Pkcs7   () ;
    case 100023                    :
    return new Encrypt::Pkcs12  () ;
    case 100024                    :
    return new Encrypt::x509    () ;
    case 100025                    :
    return new Encrypt::x509v3  () ;
  }                                ;
  return NULL                      ;
}
