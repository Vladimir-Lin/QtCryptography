/****************************************************************************
 *                                                                          *
 * Copyright (C) 2015 Neutrino International Inc.                           *
 *                                                                          *
 * Author : Brian Lin <lin.foxman@gmail.com>, Skype: wolfram_lin            *
 *                                                                          *
 ****************************************************************************/

#ifndef QT_CRYPTOGRAPHY_H
#define QT_CRYPTOGRAPHY_H

#include <QtCore>
#include <Essentials>

QT_BEGIN_NAMESPACE

#ifndef QT_STATIC
#    if defined(QT_BUILD_QTCRYPTOGRAPHY_LIB)
#      define Q_CRYPTOGRAPHY_EXPORT Q_DECL_EXPORT
#    else
#      define Q_CRYPTOGRAPHY_EXPORT Q_DECL_IMPORT
#    endif
#else
#    define Q_CRYPTOGRAPHY_EXPORT
#endif

namespace N
{

class Q_CRYPTOGRAPHY_EXPORT Encryptor ;
class Q_CRYPTOGRAPHY_EXPORT Decryptor ;

namespace Encrypt
{

class Q_CRYPTOGRAPHY_EXPORT Aes      ;
class Q_CRYPTOGRAPHY_EXPORT Des      ;
class Q_CRYPTOGRAPHY_EXPORT Rsa      ;
class Q_CRYPTOGRAPHY_EXPORT Dsa      ;
class Q_CRYPTOGRAPHY_EXPORT DH       ;
class Q_CRYPTOGRAPHY_EXPORT EC       ;
class Q_CRYPTOGRAPHY_EXPORT Blowfish ;
class Q_CRYPTOGRAPHY_EXPORT Cast     ;
class Q_CRYPTOGRAPHY_EXPORT Idea     ;
class Q_CRYPTOGRAPHY_EXPORT Rc2      ;
class Q_CRYPTOGRAPHY_EXPORT Rc4      ;
class Q_CRYPTOGRAPHY_EXPORT Rc5      ;
class Q_CRYPTOGRAPHY_EXPORT Md2      ;
class Q_CRYPTOGRAPHY_EXPORT Md4      ;
class Q_CRYPTOGRAPHY_EXPORT Md5      ;
class Q_CRYPTOGRAPHY_EXPORT Mdc2     ;
class Q_CRYPTOGRAPHY_EXPORT Sha      ;
class Q_CRYPTOGRAPHY_EXPORT RipeMd   ;
class Q_CRYPTOGRAPHY_EXPORT Asn1     ;
class Q_CRYPTOGRAPHY_EXPORT Oscp     ;
class Q_CRYPTOGRAPHY_EXPORT Pem      ;
class Q_CRYPTOGRAPHY_EXPORT Pkcs7    ;
class Q_CRYPTOGRAPHY_EXPORT Pkcs12   ;
class Q_CRYPTOGRAPHY_EXPORT x509     ;
class Q_CRYPTOGRAPHY_EXPORT x509v3   ;

}

namespace Decrypt
{

class Q_CRYPTOGRAPHY_EXPORT Aes      ;
class Q_CRYPTOGRAPHY_EXPORT Des      ;
class Q_CRYPTOGRAPHY_EXPORT Rsa      ;
class Q_CRYPTOGRAPHY_EXPORT Dsa      ;
class Q_CRYPTOGRAPHY_EXPORT DH       ;
class Q_CRYPTOGRAPHY_EXPORT EC       ;
class Q_CRYPTOGRAPHY_EXPORT Blowfish ;
class Q_CRYPTOGRAPHY_EXPORT Cast     ;
class Q_CRYPTOGRAPHY_EXPORT Idea     ;
class Q_CRYPTOGRAPHY_EXPORT Rc2      ;
class Q_CRYPTOGRAPHY_EXPORT Rc4      ;
class Q_CRYPTOGRAPHY_EXPORT Rc5      ;
class Q_CRYPTOGRAPHY_EXPORT Asn1     ;
class Q_CRYPTOGRAPHY_EXPORT Oscp     ;
class Q_CRYPTOGRAPHY_EXPORT Pem      ;
class Q_CRYPTOGRAPHY_EXPORT Pkcs7    ;
class Q_CRYPTOGRAPHY_EXPORT Pkcs12   ;
class Q_CRYPTOGRAPHY_EXPORT x509     ;
class Q_CRYPTOGRAPHY_EXPORT x509v3   ;

}

Q_CRYPTOGRAPHY_EXPORT CUIDs       Encryptors (void) ;
Q_CRYPTOGRAPHY_EXPORT CUIDs       Decryptors (void) ;
Q_CRYPTOGRAPHY_EXPORT Encryptor * encryptor  (int type) ;
Q_CRYPTOGRAPHY_EXPORT Decryptor * decryptor  (int type) ;

class Q_CRYPTOGRAPHY_EXPORT Encryptor
{
  public:

    VarArgs    Arguments ;
    QByteArray Key       ;

    explicit            Encryptor (void) ;
    virtual            ~Encryptor (void) ;

    virtual bool        supports  (int algorithm) = 0 ;
    virtual int         type      (void) const = 0 ;
    virtual QString     name      (void) = 0 ;
    virtual QStringList Methods   (void) = 0 ;
    virtual CUIDs       Bits      (void) = 0 ;
    virtual bool        encrypt   (QByteArray & input,QByteArray & output) = 0 ;

    QString             PickKey   (QString source,int length) ;

  protected:

    void                CopyKey   (QString key,unsigned char * k,int length) ;

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Decryptor
{
  public:

    VarArgs    Arguments ;
    QByteArray Key       ;

    explicit            Decryptor (void) ;
    virtual            ~Decryptor (void) ;

    virtual bool        supports  (int algorithm) = 0 ;
    virtual int         type      (void) const = 0 ;
    virtual QString     name      (void) = 0 ;
    virtual QStringList Methods   (void) = 0 ;
    virtual CUIDs       Bits      (void) = 0 ;
    virtual bool        decrypt   (QByteArray & input,QByteArray & output) = 0 ;

  protected:

    void                CopyKey   (QString key,unsigned char * k,int length) ;

  private:

};

namespace Encrypt
{

class Q_CRYPTOGRAPHY_EXPORT Aes : public Encryptor
{
  public:

    explicit Aes (void) ;
    virtual ~Aes (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100001
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Des : public Encryptor
{
  public:

    explicit Des (void) ;
    virtual ~Des (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100002
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Rsa : public Encryptor
{
  public:

    explicit Rsa (void) ;
    virtual ~Rsa (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100003
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Dsa : public Encryptor
{
  public:

    explicit Dsa (void) ;
    virtual ~Dsa (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100004
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Blowfish : public Encryptor
{
  public:

    explicit Blowfish (void) ;
    virtual ~Blowfish (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100005
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Cast : public Encryptor
{
  public:

    explicit Cast (void) ;
    virtual ~Cast (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100006
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Idea : public Encryptor
{
  public:

    explicit Idea (void) ;
    virtual ~Idea (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100007
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Rc2 : public Encryptor
{
  public:

    explicit Rc2 (void) ;
    virtual ~Rc2 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100008
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Rc4 : public Encryptor
{
  public:

    explicit Rc4 (void) ;
    virtual ~Rc4 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100009
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Rc5 : public Encryptor
{
  public:

    explicit Rc5 (void) ;
    virtual ~Rc5 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100010
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT DH : public Encryptor
{
  public:

    explicit DH (void) ;
    virtual ~DH (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100011
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT EC : public Encryptor
{
  public:

    explicit EC (void) ;
    virtual ~EC (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100012
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Md2 : public Encryptor
{
  public:

    explicit Md2 (void) ;
    virtual ~Md2 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100013
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Md4 : public Encryptor
{
  public:

    explicit Md4 (void) ;
    virtual ~Md4 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100014
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Md5 : public Encryptor
{
  public:

    explicit Md5 (void) ;
    virtual ~Md5 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100015
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Mdc2 : public Encryptor
{
  public:

    explicit Mdc2 (void) ;
    virtual ~Mdc2 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100016
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Sha : public Encryptor
{
  public:

    explicit Sha (void) ;
    virtual ~Sha (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100017
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT RipeMd : public Encryptor
{
  public:

    explicit RipeMd (void) ;
    virtual ~RipeMd (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100018
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Asn1 : public Encryptor
{
  public:

    explicit Asn1 (void) ;
    virtual ~Asn1 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100019
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Oscp : public Encryptor
{
  public:

    explicit Oscp (void) ;
    virtual ~Oscp (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100020
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Pem : public Encryptor
{
  public:

    explicit Pem (void) ;
    virtual ~Pem (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100021
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Pkcs7 : public Encryptor
{
  public:

    explicit Pkcs7 (void) ;
    virtual ~Pkcs7 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100022
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Pkcs12 : public Encryptor
{
  public:

    explicit Pkcs12 (void) ;
    virtual ~Pkcs12 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100023
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT x509 : public Encryptor
{
  public:

    explicit x509 (void) ;
    virtual ~x509 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100024
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT x509v3 : public Encryptor
{
  public:

    explicit x509v3 (void) ;
    virtual ~x509v3 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100025
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        encrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

}

namespace Decrypt
{

class Q_CRYPTOGRAPHY_EXPORT Aes : public Decryptor
{
  public:

    explicit Aes (void) ;
    virtual ~Aes (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100001
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Des : public Decryptor
{
  public:

    explicit Des (void) ;
    virtual ~Des (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100002
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Rsa : public Decryptor
{
  public:

    explicit Rsa (void) ;
    virtual ~Rsa (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100003
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Dsa : public Decryptor
{
  public:

    explicit Dsa (void) ;
    virtual ~Dsa (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100004
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Blowfish : public Decryptor
{
  public:

    explicit Blowfish (void) ;
    virtual ~Blowfish (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100005
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Cast : public Decryptor
{
  public:

    explicit Cast (void) ;
    virtual ~Cast (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100006
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Idea : public Decryptor
{
  public:

    explicit Idea (void) ;
    virtual ~Idea (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100007
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Rc2 : public Decryptor
{
  public:

    explicit Rc2 (void) ;
    virtual ~Rc2 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100008
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Rc4 : public Decryptor
{
  public:

    explicit Rc4 (void) ;
    virtual ~Rc4 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100009
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Rc5 : public Decryptor
{
  public:

    explicit Rc5 (void) ;
    virtual ~Rc5 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100010
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT DH : public Decryptor
{
  public:

    explicit DH (void) ;
    virtual ~DH (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100011
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT EC : public Decryptor
{
  public:

    explicit EC (void) ;
    virtual ~EC (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100012
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Asn1 : public Decryptor
{
  public:

    explicit Asn1 (void) ;
    virtual ~Asn1 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100019
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Oscp : public Decryptor
{
  public:

    explicit Oscp (void) ;
    virtual ~Oscp (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100020
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Pem : public Decryptor
{
  public:

    explicit Pem (void) ;
    virtual ~Pem (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100021
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Pkcs7 : public Decryptor
{
  public:

    explicit Pkcs7 (void) ;
    virtual ~Pkcs7 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100022
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT Pkcs12 : public Decryptor
{
  public:

    explicit Pkcs12 (void) ;
    virtual ~Pkcs12 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100023
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT x509 : public Decryptor
{
  public:

    explicit x509 (void) ;
    virtual ~x509 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100024
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

class Q_CRYPTOGRAPHY_EXPORT x509v3 : public Decryptor
{
  public:

    explicit x509v3 (void) ;
    virtual ~x509v3 (void) ;

    virtual bool        supports (int algorithm) ;
    virtual int         type     (void) const ; // 100025
    virtual QString     name     (void) ;
    virtual QStringList Methods  (void) ;
    virtual CUIDs       Bits     (void) ;
    virtual bool        decrypt  (QByteArray & input,QByteArray & output) ;

  protected:

  private:

};

}

}

Q_DECLARE_METATYPE(N::Encrypt::Aes)
Q_DECLARE_METATYPE(N::Encrypt::Des)
Q_DECLARE_METATYPE(N::Encrypt::Rsa)
Q_DECLARE_METATYPE(N::Encrypt::Dsa)
Q_DECLARE_METATYPE(N::Encrypt::DH)
Q_DECLARE_METATYPE(N::Encrypt::EC)
Q_DECLARE_METATYPE(N::Encrypt::Blowfish)
Q_DECLARE_METATYPE(N::Encrypt::Cast)
Q_DECLARE_METATYPE(N::Encrypt::Idea)
Q_DECLARE_METATYPE(N::Encrypt::Rc2)
Q_DECLARE_METATYPE(N::Encrypt::Rc4)
Q_DECLARE_METATYPE(N::Encrypt::Rc5)
Q_DECLARE_METATYPE(N::Encrypt::Md2)
Q_DECLARE_METATYPE(N::Encrypt::Md4)
Q_DECLARE_METATYPE(N::Encrypt::Md5)
Q_DECLARE_METATYPE(N::Encrypt::Mdc2)
Q_DECLARE_METATYPE(N::Encrypt::Sha)
Q_DECLARE_METATYPE(N::Encrypt::RipeMd)
Q_DECLARE_METATYPE(N::Encrypt::Asn1)
Q_DECLARE_METATYPE(N::Encrypt::Oscp)
Q_DECLARE_METATYPE(N::Encrypt::Pem)
Q_DECLARE_METATYPE(N::Encrypt::Pkcs7)
Q_DECLARE_METATYPE(N::Encrypt::Pkcs12)
Q_DECLARE_METATYPE(N::Encrypt::x509)
Q_DECLARE_METATYPE(N::Encrypt::x509v3)

Q_DECLARE_METATYPE(N::Decrypt::Aes)
Q_DECLARE_METATYPE(N::Decrypt::Des)
Q_DECLARE_METATYPE(N::Decrypt::Rsa)
Q_DECLARE_METATYPE(N::Decrypt::Dsa)
Q_DECLARE_METATYPE(N::Decrypt::DH)
Q_DECLARE_METATYPE(N::Decrypt::EC)
Q_DECLARE_METATYPE(N::Decrypt::Blowfish)
Q_DECLARE_METATYPE(N::Decrypt::Cast)
Q_DECLARE_METATYPE(N::Decrypt::Idea)
Q_DECLARE_METATYPE(N::Decrypt::Rc2)
Q_DECLARE_METATYPE(N::Decrypt::Rc4)
Q_DECLARE_METATYPE(N::Decrypt::Rc5)
Q_DECLARE_METATYPE(N::Decrypt::Asn1)
Q_DECLARE_METATYPE(N::Decrypt::Oscp)
Q_DECLARE_METATYPE(N::Decrypt::Pem)
Q_DECLARE_METATYPE(N::Decrypt::Pkcs7)
Q_DECLARE_METATYPE(N::Decrypt::Pkcs12)
Q_DECLARE_METATYPE(N::Decrypt::x509)
Q_DECLARE_METATYPE(N::Decrypt::x509v3)

Q_DECLARE_INTERFACE(N::Encryptor , "com.neutrino.data.encryptor" )
Q_DECLARE_INTERFACE(N::Decryptor , "com.neutrino.data.decryptor" )

QT_END_NAMESPACE

#endif
