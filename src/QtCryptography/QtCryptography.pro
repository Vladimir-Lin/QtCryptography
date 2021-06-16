NAME         = QtCryptography
TARGET       = $${NAME}

QT           = core
QT          += Essentials

load(qt_module)

INCLUDEPATH += $${PWD}/../../include/$${NAME}

HEADERS     += $${PWD}/../../include/$${NAME}/qtcryptography.h

SOURCES     += $${PWD}/nEncryptor.cpp
SOURCES     += $${PWD}/nDecryptor.cpp
SOURCES     += $${PWD}/nAESdecryptor.cpp
SOURCES     += $${PWD}/nAESencryptor.cpp
SOURCES     += $${PWD}/nDESdecryptor.cpp
SOURCES     += $${PWD}/nDESencryptor.cpp
SOURCES     += $${PWD}/nRSAdecryptor.cpp
SOURCES     += $${PWD}/nRSAencryptor.cpp
SOURCES     += $${PWD}/nDSAdecryptor.cpp
SOURCES     += $${PWD}/nDSAencryptor.cpp
SOURCES     += $${PWD}/nBlowfishDecryptor.cpp
SOURCES     += $${PWD}/nBlowfishEncryptor.cpp
SOURCES     += $${PWD}/nCASTdecryptor.cpp
SOURCES     += $${PWD}/nCASTencryptor.cpp
SOURCES     += $${PWD}/nIDEAdecryptor.cpp
SOURCES     += $${PWD}/nIDEAencryptor.cpp
SOURCES     += $${PWD}/nRC2decryptor.cpp
SOURCES     += $${PWD}/nRC2encryptor.cpp
SOURCES     += $${PWD}/nRC4decryptor.cpp
SOURCES     += $${PWD}/nRC4encryptor.cpp
SOURCES     += $${PWD}/nRC5decryptor.cpp
SOURCES     += $${PWD}/nRC5encryptor.cpp
SOURCES     += $${PWD}/nDHdecryptor.cpp
SOURCES     += $${PWD}/nDHencryptor.cpp
SOURCES     += $${PWD}/nECdecryptor.cpp
SOURCES     += $${PWD}/nECencryptor.cpp
SOURCES     += $${PWD}/nMD2encryptor.cpp
SOURCES     += $${PWD}/nMD4encryptor.cpp
SOURCES     += $${PWD}/nMD5encryptor.cpp
SOURCES     += $${PWD}/nMDC2encryptor.cpp
SOURCES     += $${PWD}/nSHAencryptor.cpp
SOURCES     += $${PWD}/nRIPEMDencryptor.cpp
SOURCES     += $${PWD}/nASN1decryptor.cpp
SOURCES     += $${PWD}/nASN1encryptor.cpp
SOURCES     += $${PWD}/nOSCPdecryptor.cpp
SOURCES     += $${PWD}/nOSCPencryptor.cpp
SOURCES     += $${PWD}/nPEMdecryptor.cpp
SOURCES     += $${PWD}/nPEMencryptor.cpp
SOURCES     += $${PWD}/nPKCS7decryptor.cpp
SOURCES     += $${PWD}/nPKCS7encryptor.cpp
SOURCES     += $${PWD}/nPKCS12decryptor.cpp
SOURCES     += $${PWD}/nPKCS12encryptor.cpp
SOURCES     += $${PWD}/nX509decryptor.cpp
SOURCES     += $${PWD}/nX509encryptor.cpp
SOURCES     += $${PWD}/nX509v3decryptor.cpp
SOURCES     += $${PWD}/nX509v3encryptor.cpp

win32 {

CONFIG(debug,debug|release) {
  LIBS      += -llibeay32d
  LIBS      += -lssleay32d
} else {
  LIBS      += -llibeay32
  LIBS      += -lssleay32
}

}

OTHER_FILES += $${PWD}/../../include/$${NAME}/headers.pri

include ($${PWD}/../../doc/Qt/Qt.pri)

TRNAME       = $${NAME}
include ($${PWD}/../../Translations.pri)
