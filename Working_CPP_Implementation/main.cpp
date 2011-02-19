#include "dll.h"
#include <iostream>
#include <time.h>

using namespace std;


typedef byte BYTE ;
typedef __int32 int32 ;
typedef __int64 long64 ;


// "heaader"
void arrayCopy(BYTE* _source, size_t _pos, size_t _len, BYTE* _dest, size_t _offset);


BYTE* SHA256(BYTE* _data, size_t _len) {
  BYTE* result = new BYTE[32];
  CryptoPP::SHA256 sha;
  sha.CalculateDigest(result, _data, _len);

  return result;
}

BYTE* AES_ENCRYPT(BYTE* _data, size_t _len, BYTE* _key, size_t * resultingCypherSize) {
  BYTE* result = 0;
  assert(CryptoPP::AES::BLOCKSIZE == 16);

  if (_len == CryptoPP::AES::BLOCKSIZE) {
    // ECB mode
    *resultingCypherSize = CryptoPP::AES::BLOCKSIZE;
    result = new BYTE[*resultingCypherSize];
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecbEncryption(_key, 32);
    ecbEncryption.ProcessData(result, _data, 16);
  } else {
    // CBC mode
    CryptoPP::AutoSeededRandomPool rnd;
    // Generate a random IV
    BYTE iv[CryptoPP::AES::BLOCKSIZE];
    rnd.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);

    result = new BYTE[_len + CryptoPP::AES::BLOCKSIZE];
    *resultingCypherSize = _len + CryptoPP::AES::BLOCKSIZE;
    
    // CBC mode
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(_key, 32, iv);
    // encrypt
    cbcEncryption.ProcessData(result+16, _data, _len);
    // copy IV to front:
    arrayCopy(iv, 0, CryptoPP::AES::BLOCKSIZE, result, 0);
  }

  return result;
}

BYTE* AES_DECRYPT(BYTE* _data, size_t _len, BYTE* _key, size_t * resultingPlaintextSize) {
  BYTE* result = 0;

  assert(CryptoPP::AES::BLOCKSIZE == 16);

  if (_len == CryptoPP::AES::BLOCKSIZE) {
    // ECB mode
    result = new BYTE[_len];
    *resultingPlaintextSize = CryptoPP::AES::BLOCKSIZE;
    CryptoPP::ECB_Mode<CryptoPP::AES >::Decryption aesDec(_key, 32);
    aesDec.ProcessData(result, _data, CryptoPP::AES::BLOCKSIZE);
  } else {
    // CBC mode
    *resultingPlaintextSize = _len - CryptoPP::AES::BLOCKSIZE;
    result = new BYTE[*resultingPlaintextSize];
    CryptoPP::CBC_Mode<CryptoPP::AES >::Decryption aesDec(_key, 32, _data);
    aesDec.ProcessData(result, _data + CryptoPP::AES::BLOCKSIZE, _len - CryptoPP::AES::BLOCKSIZE);
  }

  return result;
}

void RANDOM_FILL(BYTE* _data, size_t _len) {
  static CryptoPP::AutoSeededRandomPool rnd;
  rnd.GenerateBlock(_data, _len);
}


////////////// TEST DATA
/* file: out (20.01.2011 14:49:48)
   StartOffset: 00000000, EndOffset: 00000099, Length: 0000009A
  --> this file was encrypted with the password "test" and the filename is "out" <--
  the plaintext was "this is a testfile"
   */
unsigned char rawData[154] = {
	0x01, 0x00, 0x7B, 0x3D, 0x38, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x45, 0x3B,
	0x04, 0xD1, 0x13, 0xF6, 0xE0, 0xCA, 0xB9, 0xC1, 0x8B, 0x45, 0xE8, 0xCB,
	0xA8, 0xB7, 0x67, 0xC2, 0x8E, 0xBF, 0xC9, 0x15, 0x6C, 0x53, 0x05, 0x86,
	0x58, 0xA8, 0x71, 0xF4, 0x3E, 0x38, 0x3E, 0x92, 0x1F, 0xFC, 0xFC, 0xEB,
	0x61, 0xAE, 0xA1, 0x14, 0xFC, 0xBA, 0xA6, 0x12, 0xA5, 0xC0, 0xE6, 0x1B,
	0x4D, 0xCC, 0xB3, 0x61, 0x7B, 0xD1, 0xD2, 0xCB, 0xD8, 0xC2, 0x8C, 0xFE,
	0xA6, 0x06, 0x15, 0x27, 0xCE, 0xF8, 0xA8, 0x71, 0xEE, 0xC1, 0xB9, 0x96,
	0x8F, 0xF2, 0x37, 0xF3, 0xCD, 0xDD, 0x94, 0xF7, 0x35, 0xF4, 0x67, 0xAA,
	0xAA, 0xA1, 0x2E, 0xBD, 0xCE, 0xFF, 0xB6, 0xF6, 0xF4, 0xDB, 0xBC, 0x85,
	0x98, 0xD8, 0xE5, 0xEE, 0xD6, 0x36, 0x8D, 0x40, 0x62, 0xF4, 0x19, 0x99,
	0x46, 0xA8, 0x2B, 0x07, 0x29, 0xC5, 0xE3, 0x35, 0xFA, 0x35, 0x43, 0xDB,
	0xEB, 0xE3, 0x79, 0x1B, 0x38, 0x7B, 0x02, 0x7A, 0x1D, 0xCF, 0x5F, 0x33,
	0xB2, 0x40, 0x38, 0x60, 0xCC, 0x32, 0x0B, 0x21, 0xBE, 0x9A
};
////////////// END TEST DATA

int32 bytesToInt(BYTE* _data, size_t _count) {
  int32 shift = 0;
  int32 mask = 0;
  int32 result = 0;
  size_t i = 0;
  if (_count > 4) {
    printf("TOO long64 FOR AN int32!");
    exit(1);
  }
  if (sizeof(int32) < 4) {
    printf("INVALID int32 SIZE");
    exit(1);
  }

  for (i=0; i< _count; i++) {
    mask = 0xFF << shift;
    result = result | (_data[i] << shift);
    shift += 8;
  } 
  return result;
}

long64 bytesToLong(BYTE* _data, size_t _count) {
  int32 shift = 0;
  long64 mask = 0;
  long64 result = 0;
  size_t i = 0;
  if (_count > 8) {
    printf("TOO LONG FOR A long64!");
    exit(1);
  }
  if (sizeof(long64) < 8) {
    printf("INVALID long64 SIZE!");
    exit(1);
  }

  for (i=0; i< _count; i++) {
    mask = 0xFF << shift;
    result = result | (_data[i] << shift);
    shift += 8;
  } 
  return result;
}

void longToBytes(long64 _value, BYTE* _output, size_t _count) {
  int32 shift = 0;
  size_t i = 0;
  if (_count != 8) {
    printf("INVALID LENGTH FOR A long64!");
    exit(1);
  }
  if (sizeof(long64) < 8) {
    printf("INVALID long64 SIZE!");
    exit(1);
  }

  for (i=0; i< _count; i++) {
    _output[i] = ((_value >> shift) & 0xFF);
    shift += 8;
  } 
}

void intToBytes(int32 _value, BYTE* _output, size_t _count) {
  int32 shift = 0;
  size_t i = 0;
  if (_count != 4) {
    printf("INVALID LENGTH FOR A int32!");
    exit(1);
  }
  if (sizeof(int32) < 4) {
    printf("INVALID int32 SIZE!");
    exit(1);
  }

  for (i=0; i< _count; i++) {
    _output[i] = ((_value >> shift) & 0xFF);
    shift += 8;
  }
}

void arrayCopy(BYTE* _source, size_t _pos, size_t _len, BYTE* _dest, size_t _offset) {
  size_t i;
  for (i=0; i<_len; i++) {
    _dest[i+_offset] = _source[_pos + i];
  }
}

int arrayCompare(BYTE* _a1, BYTE* _a2, size_t _len) {
  size_t i;
  for (i=0; i<_len; i++) {
    if (_a1[i] != _a2[i]) {
      return 0;
    }
  }
  return 1;
}


BYTE* encrypt(BYTE* _data, size_t _datal, BYTE* _fname, size_t _fnamel, BYTE* _key, size_t _keyl, size_t * _resultl) {
  BYTE version[2];
  BYTE timestamp[8];
  BYTE keysalt[32];
  BYTE* keyHashedOnce;
  BYTE* keyHashedTwice;
  BYTE* paddedData;
  size_t paddedLength;
  BYTE* datahash;
  size_t encryptedSize = 0;
  BYTE* encrypted = 0;
  BYTE* result = 0;

  // version
  version[0] = 0x01; version[1] = 0x00;
  // get current time
  time_t seconds;
  seconds = time (0); 
  longToBytes((long64)seconds, timestamp, 8);

  {
    BYTE* saltedKey = 0;
    BYTE tmp2[32+32]; // will contain data for hashing a second time
    // create salt
    RANDOM_FILL(keysalt, 32);
    saltedKey = new BYTE[_keyl + 32];
    arrayCopy(_key, 0, _keyl, saltedKey, 0);
    arrayCopy(keysalt, 0, 32, saltedKey, _keyl);

    keyHashedOnce = SHA256(saltedKey, _keyl + 32);
    
    arrayCopy(keyHashedOnce, 0, 32, tmp2, 0);
    arrayCopy(keysalt, 0, 32, tmp2, 32);
    keyHashedTwice = SHA256(tmp2, 32 + 32);
    delete[] saltedKey;
  }
  
  // create data for control hash
  {
    size_t MULTIPLE = 16;
    size_t tooMuch = (_datal + 4) % MULTIPLE;
    size_t padBytes = MULTIPLE - tooMuch;
    BYTE* padding = 0;
    BYTE* hashMe = 0;
    paddedLength = _datal + padBytes + 4;
    paddedData = new BYTE[paddedLength];
    intToBytes(_datal, paddedData, 4);
    arrayCopy(_data, 0, _datal, paddedData, 4);
    // make random padding
    padding = new BYTE[padBytes];
    RANDOM_FILL(padding, padBytes);
    arrayCopy(padding, 0, padBytes, paddedData, 4 + _datal);

    //now create actual control hash:
    size_t dataToHashLength = 2 + 8 + _fnamel + paddedLength;
    hashMe = new BYTE[dataToHashLength];
    size_t pos = 0;
    arrayCopy(version, 0, 2, hashMe, pos); pos+=2;
    arrayCopy(timestamp, 0, 8, hashMe, pos); pos += 8;
    arrayCopy(_fname, 0, _fnamel, hashMe, pos); pos += _fnamel;
    arrayCopy(paddedData, 0, paddedLength, hashMe, pos);
    datahash = SHA256(hashMe, dataToHashLength);
    delete[] hashMe;
    delete[] padding;
  }

  // encryption stuff
  {
    size_t encryptLength = 32 + paddedLength;
    BYTE* encryptMe = new BYTE[encryptLength];
    arrayCopy(datahash, 0, 32, encryptMe, 0);
    arrayCopy(paddedData, 0, paddedLength, encryptMe, 32);
    encrypted = AES_ENCRYPT(encryptMe, encryptLength, keyHashedOnce, &encryptedSize);
    delete[] encryptMe;
  }

  *_resultl = 2 + 8 + 32 + 32 + encryptedSize;
  result = new BYTE[*_resultl];
  size_t pos = 0;
  arrayCopy(version, 0, 2, result, pos); pos += 2;
  arrayCopy(timestamp, 0, 8, result, pos); pos += 8;
  arrayCopy(keyHashedTwice, 0, 32, result, pos); pos += 32;
  arrayCopy(keysalt, 0, 32, result, pos); pos += 32;
  arrayCopy(encrypted, 0, encryptedSize, result, pos); pos += encryptedSize;
  assert(pos == *_resultl);

  delete[] paddedData;
  return result; // dummy implementation
}


BYTE* decrypt(BYTE* _data, size_t _datal, BYTE* _key, size_t _keyl, size_t * _resultl, BYTE* _filename, size_t _filenamel) {
  BYTE version[2];
  BYTE timestamp[8];
  BYTE keyhash[32];
  BYTE keysalt[32];
  BYTE datahash[32];
  BYTE plainLen[4];
  long64 time = 0;
  int versionNumber;
  size_t encSize = _datal - 2*32 - 8 - 2;
  BYTE * encryptedData = &(_data[2*32 + 8 + 2]);
  size_t pos = 0;
  BYTE* keyHashedOnce;
  BYTE* keyHashedTwice;
  BYTE* decryptedData;
  size_t decryptedDataLength;
  BYTE* actualPlaintext;
  size_t actualPlaintextLength;

  arrayCopy(_data, pos, 2, version, 0);
  pos+=2;
  arrayCopy(_data, pos, 8, timestamp, 0);
  pos+=8;
  arrayCopy(_data, pos, 32, keyhash, 0);
  pos+=32;
  arrayCopy(_data, pos, 32, keysalt, 0);
  pos+=32;
  arrayCopy(_data, pos, encSize, encryptedData, 0);
  
  versionNumber = bytesToInt(version, 2);
  time = bytesToLong(timestamp, 8);

  //printf("time value = %lld\n", time);
  

  if (versionNumber != 1) {
    printf("unsupported version!\n");
    exit(1);
  } else {
    //printf("version ok\n");
  }

  // calculate key hashes
  {
    size_t tmpLen = _keyl + 32;
    BYTE* tmp = new BYTE[tmpLen]; // key + salt
    BYTE* tmp2 = new BYTE[32 + 32]; // salted&hashed key + salt
    
    arrayCopy(_key, 0, _keyl, tmp, 0);
    arrayCopy(keysalt, 0, 32, tmp, _keyl);
    keyHashedOnce = SHA256(tmp, tmpLen);

    arrayCopy(keyHashedOnce, 0, 32, tmp2, 0);
    arrayCopy(keysalt, 0, 32, tmp2, 32);
    keyHashedTwice = SHA256(tmp2, 32 + 32);
    delete[] tmp;
    delete[] tmp2;
  }

  // check if we have the right key
  if (!arrayCompare(keyHashedTwice, keyhash, 32)) {
    printf("KEY INVALID!\n");
    exit(1);
  }

  // decrypt the data
  decryptedData = AES_DECRYPT(encryptedData, encSize, keyHashedOnce, &decryptedDataLength);

  // take apart the decrypted data
  arrayCopy(decryptedData, 0, 32, datahash, 0);
  arrayCopy(decryptedData, 32, 4, plainLen, 0);

  // check the control hash:
  {
    size_t dataToHashLength = 2 + 8 + _filenamel + (decryptedDataLength - 32);
    BYTE* hashMe = new BYTE[dataToHashLength];
    BYTE* dataHashCheck = 0;
    size_t pos = 0;
    arrayCopy(version, 0, 2, hashMe, pos); pos+=2;
    arrayCopy(timestamp, 0, 8, hashMe, pos); pos += 8;
    arrayCopy(_filename, 0, _filenamel, hashMe, pos); pos += _filenamel;
    arrayCopy(decryptedData + 32, 0, decryptedDataLength - 32, hashMe, pos);
    dataHashCheck = SHA256(hashMe, dataToHashLength);

    if (!arrayCompare(datahash, dataHashCheck, 32)) {
      printf("ERROR! modification hash check failed! data corrupted\n");
      exit(1);
    } else {
      //printf("modification hash check ok\n");
    }

    delete[] dataHashCheck;
    delete[] hashMe;
  }

  actualPlaintextLength = (size_t)bytesToInt(plainLen, 4);
  *_resultl = actualPlaintextLength;
  //printf("%d bytes plaintext\n", actualPlaintextLength); // DEBUG OUTPUT
  actualPlaintext = new BYTE[actualPlaintextLength];

  // NOTE: what is not done yet here is: check the datahash if it matches what the hash would be if we construct it ourselves
  arrayCopy(decryptedData, 32 + 4, actualPlaintextLength, actualPlaintext, 0);
  
  return actualPlaintext;
}

// helper function that prints byte-array as text
void printAsASCII(BYTE* _data, size_t _len) {
    size_t i;
    for (i=0; i<_len; i++)
      printf("%c", _data[i]);
    printf("\n");
}

int writeToFile(BYTE* _buf, size_t _size, char* _file) {
  // write to file
  ofstream myfile (_file, ios::binary | ios::out | ios::trunc);
  if (myfile.is_open())
  {
    myfile.write((const char*)_buf, _size);
    myfile.close();
    return 0;
  }
  else
  {
    cout << "Unable to open output file";
    return -1;
  }
}

BYTE* readFromFile(char* _file, size_t* _size) {
  ifstream  myfile;
  myfile.open (_file, ios::binary | ios::in | ios::ate);
  if (!myfile.is_open())
  {
    cout << "could not open file!" << endl;
    *_size = 0;
    return 0;
  }
  *_size = myfile.tellg();
  BYTE * memblock = new BYTE [*_size];
  myfile.seekg (0, ios::beg);
  myfile.read ((char*)memblock, *_size);
  myfile.close();
  return memblock;
}

////////////////////////////////////
///        TEST MAIN METHOD
////////////////////////////////////
int __cdecl main()
{
  {
  // test program that encrypts encryptMe.txt, writes it to a file, and decrypts it again
  char* fileName = "encryptMe.txt";
  char* fileName2 = "encryptMe.txt.out";
  char* fileName3 = "encryptMe.txt.out.out";
  BYTE* key = (BYTE*)"test";
  size_t size = 0;
  BYTE* memblock = readFromFile(fileName, &size);
  if (memblock == 0) {
    printf("error reading file!\n");
    return -1;
  }
  
  BYTE* encryptedResult;
  size_t encryptedLength;

  encryptedResult = encrypt(memblock, size, (BYTE*)fileName2, strlen(fileName2), key, 4, &encryptedLength);
  
  int success = writeToFile(encryptedResult, encryptedLength, fileName2);
  if (success != 0) {
      printf("ERROR WRITING TO FILE\n");
      return -1;
  }
  delete[] encryptedResult;
  encryptedResult = 0;

  // read in again
  delete[] memblock;
  memblock = readFromFile(fileName2, &size);
  if (memblock == 0) {
    printf("error reading file!\n");
    return -1;
  }

  // decrypt again
  size_t resultlength = -1;

  BYTE* decryptedResult = decrypt(memblock, size, key, 4, &resultlength, (BYTE*)fileName2, strlen(fileName2));
  
  success = writeToFile(decryptedResult, resultlength, fileName3);
  if (success != 0) {
      cout << "Unable to open output file";
      return -1;
  }

  delete[] memblock;
  
  return 0;
  } // end new main
  
  // old main:

  { // int<->bytes test
    BYTE test[20];
    int32 before = 152846999;
    intToBytes(before, test, 4);
    int result = bytesToInt(test, 4);
    assert (result == before);
  }

  { // test cryptographic functions
    BYTE testdata[32];
    BYTE key[32];
    for (int i=0; i<32; i++) {
      testdata[i] = i;
      key[i] = 2*i;
    }
    size_t encSize = 0;
    size_t plainSize = 0;
    BYTE* enc = AES_ENCRYPT(testdata, 32, key, &encSize);
    BYTE* dec = AES_DECRYPT(enc, encSize, key, &plainSize);
    int equal = arrayCompare(testdata, dec, plainSize);
    assert(equal != 0);
    printf("AES check ok\n");
  }

  char* password = "test";
  char* filename = "out";
  BYTE* key = (BYTE*)password; // NOTE: if it contains special-chars - "umlauts" ;) - you would have to get the correct utf8-encoding
  size_t resultlength;

  BYTE* decryptedResult;
  
  decryptedResult = decrypt(rawData, 154, key, 4, &resultlength, (BYTE*)filename, strlen(filename));
  // decryptedResult is the plaintext as byte[], you have to convert it back to text (if its just ASCII chars, you can treat is as char[])
  
  // DEBUG OUTPUT
  printAsASCII(decryptedResult, resultlength);


  // encrypt & decrypt
  {
    char* encryptMe = "another crypto test 1234 check check";
    char* fileName = "out";
    BYTE* encryptMeInBytes = (BYTE*)encryptMe;
  
    BYTE* encryptedResult;
    size_t encryptedLength;

    encryptedResult = encrypt(encryptMeInBytes, strlen(encryptMe), (BYTE*)fileName, strlen(fileName), key, 4, &encryptedLength);
    // decrypt again
    decryptedResult = decrypt(encryptedResult, encryptedLength, key, strlen(password), &resultlength, (BYTE*)filename, strlen(filename));
    // decryptedResult is the plaintext as byte[], you have to convert it back to text (if its just ASCII chars, you can treat is as char[])

    // DEBUG OUTPUT
    printAsASCII(decryptedResult, resultlength);
  }

	return 0;
}

/*
int __cdecl main() {
  cout << "test..." << endl;

  byte output[32];
  byte input[4];
  input[0] = 'h';
  input[1] = 'e';
  input[2] = 'l';
  input[3] = 'o';

  CryptoPP::SHA256 sha;
  sha.CalculateDigest(output, input, 4);

  cout << "got: ";
  cout.fill('0');
  cout.width(2);
  cout.flags(cout.hex);
  
  for(int i=0; i<32; i++) {
    printf("%02X", output[i]);
  }

  cout << endl;
  cout << "end";


  CryptoPP::AESDecryption aesd;
  //aesd.SetKeyWithIV(
  
}
*/
