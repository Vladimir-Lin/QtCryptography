#include <qtcryptography>
#include <openssl/dsa.h>

N::Encrypt::Dsa:: Dsa       (void)
                : Encryptor (    )
{
}

N::Encrypt::Dsa::~Dsa (void)
{
}

bool N::Encrypt::Dsa::supports (int algorithm)
{
  return ( Cryptography::Signature == algorithm ) ;
}

int N::Encrypt::Dsa::type(void) const
{
  return 100004 ;
}

QString N::Encrypt::Dsa::name(void)
{
  return QString("DSA") ;
}

QStringList N::Encrypt::Dsa::Methods(void)
{
  QStringList E ;
  E << "Normal" ;
  return E      ;
}

CUIDs N::Encrypt::Dsa::Bits(void)
{
  CUIDs  IDs  ;
  IDs <<   64 ;
  IDs <<  128 ;
  IDs <<  256 ;
  IDs <<  384 ;
  IDs <<  512 ;
  IDs <<  768 ;
  IDs << 1024 ;
  IDs << 2048 ;
  IDs << 3072 ;
  IDs << 4096 ;
  return IDs  ;
}

bool N::Encrypt::Dsa::encrypt(QByteArray & input,QByteArray & output)
{
  if (Arguments.count()< 3) return false                  ;
  if (input    .size ()<=0) return false                  ;
  /////////////////////////////////////////////////////////
  int  bits    = Arguments[0].toInt()                     ;
  bool correct = false                                    ;
  if ( bits ==   64 ) correct = true                      ;
  if ( bits ==  128 ) correct = true                      ;
  if ( bits ==  256 ) correct = true                      ;
  if ( bits ==  384 ) correct = true                      ;
  if ( bits ==  512 ) correct = true                      ;
  if ( bits ==  768 ) correct = true                      ;
  if ( bits == 1024 ) correct = true                      ;
  if ( bits == 2048 ) correct = true                      ;
  if ( bits == 3072 ) correct = true                      ;
  if ( bits == 4096 ) correct = true                      ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////
  QString mode    = Arguments[1].toString()               ;
  mode    = mode.toUpper()                                ;
  correct = false                                         ;
  if ( "Normal" == mode ) correct = true                  ;
  if (!correct) return false                              ;
  /////////////////////////////////////////////////////////

#ifdef XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

  DSA* dsa = DSA_new();
  DSA_generate_parameters_ex(dsa,2048,NULL,0,NULL,NULL, NULL);
  DSA_generate_key(dsa);

  DSA* dsa;
  unsigned char* input_string;
  unsigned char* sign_string;
  unsigned int sig_len;
  unsigned int i;

  // check usage
  if (argc != 2) {
      fprintf(stderr, "%s <plain text>\n", argv[0]);
      exit(-1);
  }

  // set the input string
  input_string = (unsigned char*)calloc(strlen(argv[1]) + 1,
          sizeof(unsigned char));
  if (input_string == NULL) {
      fprintf(stderr, "Unable to allocate memory for input_string\n");
      exit(-1);
  }
  strncpy((char*)input_string, argv[1], strlen(argv[1]));

  // Generate random DSA parameters with 1024 bits
  dsa = DSA_generate_parameters(1024, NULL, 0, NULL, NULL, NULL, NULL);

  // Generate DSA keys
  DSA_generate_key(dsa);

  // alloc sign_string
  sign_string = (unsigned char*)calloc(DSA_size(dsa), sizeof(unsigned char));
  if (sign_string == NULL) {
      fprintf(stderr, "Unable to allocate memory for sign_string\n");
      exit(-1);
  }

  // sign input_string
  if (DSA_sign(0, input_string, strlen((char*)input_string),
              sign_string, &sig_len, dsa) == 0) {
      fprintf(stderr, "Sign Error.\n");
      exit(-1);
  }

  // verify signature and input_string
  int is_valid_signature = DSA_verify(0,
          input_string, strlen((char*)input_string),
          sign_string, sig_len, dsa);

  // print
  DSAparams_print_fp(stdout, dsa);
  printf("input_string = %s\n", input_string);
  printf("signed string = ");
  for (i=0; i<sig_len; ++i) {
      printf("%x%x", (sign_string[i] >> 4) & 0xf,
              sign_string[i] & 0xf);
  }
  printf("\n");
  printf("is_valid_signature? = %d\n", is_valid_signature);

#endif

  return true ;
}
