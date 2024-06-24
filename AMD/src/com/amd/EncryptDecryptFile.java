package com.amd;

/**
 *   Application that will Encrypt and Decrypt the file using the RSA key pair generated.
 */

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptDecryptFile {
	static SecureRandom srandom = new SecureRandom();
/*
 * Read private key from project location
 */
	private PrivateKey getPrivateKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] bytes = Files.readAllBytes(Paths.get("AMDPrivate.key"));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
		return KeyFactory.getInstance("RSA").generatePrivate(spec);
	}
	/*
	 * Read public key from project location
	 */
	private PublicKey getPublicKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] bytes = Files.readAllBytes(Paths.get("AMDPublic.key"));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
		return KeyFactory.getInstance("RSA").generatePublic(spec);
	}

	private void encrypt()
			throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		PrivateKey privateKey = getPrivateKey();

		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		SecretKey skey = kgen.generateKey();
		byte[] iv = new byte[128 / 8];
		srandom.nextBytes(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		try (FileOutputStream out = new FileOutputStream("encrypt/AMDImage.enc")) {

			{
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, privateKey);
				byte[] b = cipher.doFinal(skey.getEncoded());
				out.write(b);
			}

			out.write(iv);
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
			try (InputStream in = getClass().getClassLoader().getResourceAsStream("AMD_image.JPG")) {
				byte[] inBuffer = new byte[1024];
				int len;
				while ((len = in.read(inBuffer)) != -1) {
					byte[] outBuffer = ci.update(inBuffer, 0, len);
					if (outBuffer != null)
						out.write(outBuffer);
				}
				byte[] outBuffer = ci.doFinal();
				if (outBuffer != null)
					out.write(outBuffer);
			}
		}
		System.out.println("File Encrypted successfully...");

	}

	private void decrypt()
			throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		PublicKey publicKey = getPublicKey();

		try (InputStream in = getClass().getClassLoader().getResourceAsStream("AMDImage.enc")) {
			SecretKeySpec skey = null;
			{

				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, publicKey);
				byte[] b = new byte[256];
				in.read(b);
				byte[] keyb = cipher.doFinal(b);
				skey = new SecretKeySpec(keyb, "AES");
			}
			byte[] iv = new byte[128 / 8];
			in.read(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
			try (FileOutputStream out = new FileOutputStream("decrypt/AMD.jpg")) {
				byte[] inBuffer = new byte[1024];
				int len;
				while ((len = in.read(inBuffer)) != -1) {
					byte[] outBuffer = ci.update(inBuffer, 0, len);
					if (outBuffer != null)
						out.write(outBuffer);
				}
				byte[] outBuffer = ci.doFinal();
				if (outBuffer != null)
					out.write(outBuffer);
			}

		}
		System.out.println("File Decrypted successfully...");
	}

	public static void main(String args[])
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		EncryptDecryptFile res = new EncryptDecryptFile();
		 res.encrypt();
		//res.decrypt();
	}

}
