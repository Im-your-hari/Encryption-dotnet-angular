import { Injectable } from '@angular/core';
import * as CryptoJS from 'crypto-js';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class EncryptionService {
  private readonly keySize = 32;
  private readonly ivSize = 16;
  private readonly secretKey: string;

  constructor() {
    this.secretKey = environment.encryptionSecret;
  }

  private generateKeyAndIv(passphrase: string, salt: CryptoJS.lib.WordArray): CryptoJS.lib.WordArray {
    let totalBytes = CryptoJS.lib.WordArray.create();
    let currentHash = CryptoJS.lib.WordArray.create();
    const passphraseBytes = CryptoJS.enc.Utf8.parse(passphrase);

    while (totalBytes.sigBytes < (this.keySize + this.ivSize)) {
      const data = currentHash.concat(passphraseBytes).concat(salt);
      currentHash = CryptoJS.MD5(data);
      totalBytes = totalBytes.concat(currentHash);
    }

    return totalBytes;
  }

  decrypt(encryptedBase64: string): string {
    try {
      
      const encryptedBytes = CryptoJS.enc.Base64.parse(encryptedBase64);
      
      
      const salt = CryptoJS.lib.WordArray.create(encryptedBytes.words.slice(2, 4));
      
      
      const keyAndIv = this.generateKeyAndIv(this.secretKey, salt);
      const key = CryptoJS.lib.WordArray.create(keyAndIv.words.slice(0, this.keySize / 4));
      const iv = CryptoJS.lib.WordArray.create(keyAndIv.words.slice(this.keySize / 4, (this.keySize + this.ivSize) / 4));

      
      const ciphertext = CryptoJS.lib.WordArray.create(encryptedBytes.words.slice(4));

      
      const encryptedStr = CryptoJS.lib.CipherParams.create({
        ciphertext: ciphertext,
        key: key,
        iv: iv,
        salt: salt,
        algorithm: CryptoJS.algo.AES,
        mode: CryptoJS.mode.CBC as any,
        padding: CryptoJS.pad.Pkcs7,
        blockSize: 4,
        formatter: CryptoJS.format.OpenSSL
      }).toString();

      
      const decrypted = CryptoJS.AES.decrypt(
        encryptedStr,
        key,
        {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }
      );

      const decryptedResponse = decrypted.toString(CryptoJS.enc.Utf8);

      

      return decryptedResponse;

    } catch (error) {
      console.error('Decryption error:', error);
      throw error;
    }
  }

  
  setItem(key: string, value: any) {
    const encryptedValue = this.encrypt(JSON.stringify(value));
    localStorage.setItem(key, encryptedValue);
  }

  getItem(key: string) {
    const encryptedValue = localStorage.getItem(key);
    if (encryptedValue) {
      const decryptedValue = this.decrypt(encryptedValue);
      return JSON.parse(decryptedValue);
    }
    return null;
  }

  
  encrypt(plainText: string): string {
    try {
      
      const salt = CryptoJS.lib.WordArray.random(8);
      
      
      const keyAndIv = this.generateKeyAndIv(this.secretKey, salt);
      const key = CryptoJS.lib.WordArray.create(keyAndIv.words.slice(0, this.keySize / 4));
      const iv = CryptoJS.lib.WordArray.create(keyAndIv.words.slice(this.keySize / 4, (this.keySize + this.ivSize) / 4));

      
      const padding = CryptoJS.lib.WordArray.create([0, 0]);

      
      const encrypted = CryptoJS.AES.encrypt(plainText, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });

      
      const combined = padding.concat(salt).concat(encrypted.ciphertext);
      
      return combined.toString(CryptoJS.enc.Base64);
    } catch (error) {
      throw error;
    }
  }

}
