// <copyright file="EncryptDecrypt.cs" company="Harikrishnan">
// Copyright © Harikrishnan. All rights reserved.
// This computer program may not be used, copied, distributed, corrected, modified,
// translated, transmitted or assigned without Harikrishnan's prior written authorization.
// </copyright>
namespace Solution.Project
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// EncryptDecrypt service for encrypting and decrypting
    /// </summary>
    public class EncryptDecrypt
    {
	/// <summary>
	/// Define the KeySize
	/// </summary>
	private const int KeySize = 32;

	/// <summary>
	/// Define the IvSize
	/// </summary>
	private const int IvSize = 16;

	/// <summary>
	/// Define SecretKey
	/// </summary>
	private readonly string _secretKey;

	/// <summary>
	/// Constructor for EncryptDecrypt service
	/// </summary>
	/// <param name="secretKey"></param>
	public EncryptDecrypt(string secretKey)
	{
	    _secretKey = secretKey;
	}

	/// <summary>
	/// Method to convert plainText to AES encrypted string
	/// </summary>
	/// <param name="plainText"></param>
	/// <returns>encryptedBytes</returns>
	public string Encrypt(string plainText)
	{
	    byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
	    byte[] salt = new byte[8];

	    byte[] keyAndIv = GenerateKeyAndIv(Encoding.UTF8.GetBytes(_secretKey), salt);
	    byte[] key = keyAndIv.Take(KeySize).ToArray();
	    byte[] iv = keyAndIv.Skip(KeySize).Take(IvSize).ToArray();

	    using (var aes = Aes.Create())
	    {
		aes.Key = key;
		aes.IV = iv;
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;

		using (var encryptor = aes.CreateEncryptor())
		{
		    using (var msEncrypt = new MemoryStream())
		    {
			msEncrypt.Write(new byte[8], 0, 8);
			msEncrypt.Write(salt, 0, salt.Length);
			using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
			{
			    csEncrypt.Write(plainTextBytes, 0, plainTextBytes.Length);
			    csEncrypt.FlushFinalBlock();
			}

			byte[] encryptedBytes = msEncrypt.ToArray();

			return Convert.ToBase64String(encryptedBytes);
		    }
		}
	    }
	}

	/// <summary>
	/// Method to decrypt AES encrypted string
	/// </summary>
	/// <param name="encryptedBase64"></param>
	/// <returns>Decrypted text</returns>
	public string Decrypt(string encryptedBase64)
	{
	    byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);
	    byte[] salt = new byte[8];
	    Array.Copy(encryptedBytes, 8, salt, 0, 8);

	    byte[] keyAndIv = GenerateKeyAndIv(Encoding.UTF8.GetBytes(_secretKey), salt);
	    byte[] key = keyAndIv.Take(KeySize).ToArray();
	    byte[] iv = keyAndIv.Skip(KeySize).Take(IvSize).ToArray();
	    byte[] cipherText = new byte[encryptedBytes.Length - 16];
	    Array.Copy(encryptedBytes, 16, cipherText, 0, cipherText.Length);

	    using (var aes = Aes.Create())
	    {
		aes.Key = key;
		aes.IV = iv;
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;

		using (var decryptor = aes.CreateDecryptor())
		using (var msDecrypt = new MemoryStream(cipherText))
		using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
		using (var srDecrypt = new StreamReader(csDecrypt))
		{
		    return srDecrypt.ReadToEnd();
		}
	    }
	}

	/// <summary>
	/// Method generates the key and Iv bytes
	/// </summary>
	/// <param name="passphrase"></param>
	/// <param name="salt"></param>
	/// <returns></returns>
	private byte[] GenerateKeyAndIv(byte[] passphrase, byte[] salt)
	{
	    byte[] totalBytes = new byte[0];
	    byte[] currentHash = new byte[0];

	    using (var md5 = MD5.Create())
	    {
		while (totalBytes.Length < KeySize + IvSize)
		{
		    byte[] data = currentHash.Concat(passphrase).Concat(salt).ToArray();
		    currentHash = md5.ComputeHash(data);
		    totalBytes = totalBytes.Concat(currentHash).ToArray();
		}
	    }
	    return totalBytes;
	}
    }
}
