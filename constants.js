export const crypto_pwhash_argon2id_SALTBYTES = 16;
export const CHUNKSIZE = 1024 * 512;
export const LEGACY_CHUNKSIZE = 4096;
export const SIGNATURE = new Uint8Array([0xC1, 0x0A, 0x6B, 0xED]);
export const LEGACY_SIGNATURE = new Uint8Array([0xC1, 0x0A, 0x4B, 0xED]);

export const EXTENSION = '.cloaker';
export const START_ENCRYPTION = 'startEncryption';
export const ENCRYPT_CHUNK = 'encryptChunk';
export const ENCRYPTED_CHUNK = 'encryptedChunk';
export const START_DECRYPTION = 'startDecryption';
export const DECRYPT_CHUNK = 'decryptChunk';
export const DECRYPTED_CHUNK = 'decryptedChunk';
export const INITIALIZED_ENCRYPTION = 'initializedEncryption';
export const INITIALIZED_DECRYPTION = 'initializedDecryption';
export const FINAL_ENCRYPTION = 'finalEncryption';
export const FINAL_DECRYPTION = 'finalDecryption';
export const DECRYPTION_FAILED = 'decryptionFailed';
