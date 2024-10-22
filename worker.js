// import * as c from './constants.js';
let c = {
  crypto_pwhash_argon2id_SALTBYTES: 16,
  CHUNKSIZE: 1024 * 512,
  LEGACY_CHUNKSIZE: 4096,
  SIGNATURE: new Uint8Array([0xC1, 0x0A, 0x6B, 0xED]),
  LEGACY_SIGNATURE: new Uint8Array([0xC1, 0x0A, 0x4B, 0xED]),
  SIG_STRING: "SIMPL",
  SIG_V_TAG: "v2.0.0",
  SIG_V_NUMBER: 2024102201,
  REPO_URL: "https://github.com/A99US/simple_file_encryption",
  EXTENSION: '.cloaker',
  START_ENCRYPTION: 'startEncryption',
  ENCRYPT_CHUNK: 'encryptChunk',
  ENCRYPTED_CHUNK: 'encryptedChunk',
  START_DECRYPTION: 'startDecryption',
  DECRYPT_CHUNK: 'decryptChunk',
  DECRYPTED_CHUNK: 'decryptedChunk',
  INITIALIZED_ENCRYPTION: 'initializedEncryption',
  INITIALIZED_DECRYPTION: 'initializedDecryption',
  FINAL_ENCRYPTION: 'finalEncryption',
  FINAL_DECRYPTION: 'finalDecryption',
  DECRYPTION_FAILED: 'decryptionFailed',
  ENCRYPTION_FAILED: 'encryptionFailed',
};

const hydrate = (sodium) => {
  console.log('sodium initialized in worker');
  let state, inFile, headerFile, offset, ad;
  let legacy = false;

  let ARGON2ALGO = sodium.crypto_pwhash_ALG_ARGON2ID13, headerDec, headerInit,
      decID

  const startEncryption = (message) => {
    let { password, ops, mem } = message.data;
    let salt = sodium.randombytes_buf(c.crypto_pwhash_argon2id_SALTBYTES);
    ad = message.data.ad;
    inFile = message.data.inFile;
    headerFile = message.data.headerFile;
    offset = 0;
    headerInit = true;

    let key = sodium.crypto_pwhash(32, password, salt, (ops >>> 0), (mem >>> 0), ARGON2ALGO);
    let res = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    state = res.state;
    let header = res.header;
    postMessage({ response: c.INITIALIZED_ENCRYPTION, header, salt });
  }

  const encryptChunk = async (message) => {
    let chunk, response, progress, encryptedChunk, header_len = null;
    // Encrypting Header
    if (headerInit) {
      // If headerFile is set
      if (headerFile) {
        if(headerFile.size > c.CHUNKSIZE){
          postMessage({
            response: c.ENCRYPTION_FAILED,
            message: "Header Size is longer than "+ c.CHUNKSIZE +"!",
          });
          return;
        }
        chunk = await headerFile.arrayBuffer();
        chunk = new Uint8Array(chunk);
      }
      // If headerFile is not set, use empty header
      else {
        chunk = await sodium.randombytes_buf(0);
        chunk = new Uint8Array(chunk);
      }
      let tag = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      response = c.ENCRYPTED_CHUNK;
      encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, ad, tag);
      header_len = new Uint8Array(4);
      new DataView(header_len.buffer).setUint32(0, encryptedChunk.length, false); // false for big-endian
      //console.log("Length : "+ header_len +" And "+ encryptedChunk.length)
      progress = 0;
      headerInit = false
    }
    // Encrypting File
    else {
      let chunkSize = Math.min(c.CHUNKSIZE, inFile.size - offset);
      let chunk = await inFile.slice(offset, offset + chunkSize).arrayBuffer();
      chunk = new Uint8Array(chunk);
      offset += chunkSize;
      let tag = offset < inFile.size - 1
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
      response = tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        ? c.FINAL_ENCRYPTION
        : c.ENCRYPTED_CHUNK;
      encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, ad, tag);
      progress = Math.floor((offset/inFile.size)*100);
    }
    postMessage({ header_len, response, progress, encryptedChunk, bytesWritten: offset });
  }

  const startDecryption = async (message) => {
    let { password, ops, mem } = message.data;
    headerDec = message.data.headerDec;
    ad = message.data.ad;
    inFile = message.data.inFile;
    let salt, header, key;
    headerInit = true;
    decID = 0;
    let firstFour = await inFile.slice(0, 4).arrayBuffer();
    firstFour = new Uint8Array(firstFour);
    if (1 == 1 || compareArrays(firstFour, c.SIGNATURE)) {
      let file_SIG = new TextDecoder().decode(await inFile.slice(0, 5).arrayBuffer());
      // No SIGNATURE
      if (file_SIG != c.SIG_STRING) {
        postMessage({
          response: c.DECRYPTION_FAILED,
          message: "Input file is not an encrypted file. No Signature Found!",
        });
        return;
      }
      let file_VER_BUFF = await inFile.slice(5, 9).arrayBuffer();
      let file_VER = new DataView(file_VER_BUFF).getUint32(0, false); // false for big-endian
      // Encrypted Using Different Version
      if (file_VER != c.SIG_V_NUMBER) {
        postMessage({
          response: c.DECRYPTION_FAILED,
          message: "Can't decrypt. Input file was encrypted using another version '"+file_VER+"'!",
        });
        return;
      }
      offset = 9; //4; // skip signature
      salt = await inFile.slice(offset, offset + c.crypto_pwhash_argon2id_SALTBYTES).arrayBuffer();
      salt = new Uint8Array(salt);
      offset += c.crypto_pwhash_argon2id_SALTBYTES;
      header = await inFile.slice(offset, offset + sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES).arrayBuffer();
      header = new Uint8Array(header);
      offset += sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
      key = sodium.crypto_pwhash(32, password, salt, (ops >>> 0), (mem >>> 0), ARGON2ALGO);
    } else {
      legacy = true;
      offset = compareArrays(firstFour, c.LEGACY_SIGNATURE) ? 4 : 0; // skip signature
      salt = await inFile.slice(offset, offset + sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES).arrayBuffer();
      salt = new Uint8Array(salt);
      offset += sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
      header = await inFile.slice(offset, offset + sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES).arrayBuffer();
      header = new Uint8Array(header);
      offset += sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
      key = sodium.crypto_pwhash_scryptsalsa208sha256(32, password, salt,
        sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    }

    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
    postMessage({ response: c.INITIALIZED_DECRYPTION, header });
  }

  const decryptChunk = async (message) => {
    decID++;
    let chunkSize = legacy ? c.LEGACY_CHUNKSIZE : c.CHUNKSIZE;
    // Reading HEADER length from 'simplenc' encryption
    if(headerInit){
      let header_bytes = await inFile.slice(offset, offset+4).arrayBuffer();
      chunkSize = new DataView(header_bytes).getUint32(0, false); // false for big-endian
      chunkSize -= sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
      offset += 4;
      //console.log(chunkSize +" "+ offset +" "+ headerDec);
      headerInit = false;
    }
    chunkSize = Math.min(chunkSize + sodium.crypto_secretstream_xchacha20poly1305_ABYTES, inFile.size - offset);
    let chunk = await inFile.slice(offset, offset + chunkSize).arrayBuffer();
    chunk = new Uint8Array(chunk);
    offset += chunkSize;
    let res = sodium.crypto_secretstream_xchacha20poly1305_pull(state, chunk, ad);
    if (!res) {
      postMessage({ response: c.DECRYPTION_FAILED, message: null });
      return;
    }
    let decryptedChunk = res.message;
    const progress = headerDec ? 100 : Math.floor((offset/inFile.size)*100);
    let response = res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL || headerDec
      ? c.FINAL_DECRYPTION
      : c.DECRYPTED_CHUNK;
    postMessage({ headerDec, decID, response, progress, decryptedChunk, bytesWritten: offset });
  }

  onmessage = (message) => {
    // console.log('worker received:', message);
    switch(message.data.command) {
      case c.START_ENCRYPTION:
        startEncryption(message);
        break;
      case c.ENCRYPT_CHUNK:
        encryptChunk(message);
        break;
      case c.START_DECRYPTION:
        startDecryption(message);
        break;
      case c.DECRYPT_CHUNK:
        decryptChunk(message);
        break;
    }
  };
}
self.sodium = { onload: hydrate };
importScripts('./sodium.js');

const compareArrays = (a1, a2) => {
  if (!a1.length || a1.length != a2.length) {
    return false;
  }
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] != a2[i]) {
      return false;
    }
  }
  return true;
}
