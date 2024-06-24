package com.amd;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Application to generate an RSA key pair, key size = 2048 bits 
 * 
 */
public class RSAKeyPair {

	public static KeyPair generatePublicPrivateKey() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair keyPair = generator.generateKeyPair();

		try(FileOutputStream out = new FileOutputStream("AMDPrivate.key")){
			out.write(keyPair.getPrivate().getEncoded());
			
		}
		try(FileOutputStream out = new FileOutputStream("AMDPublic.key")){
			out.write(keyPair.getPublic().getEncoded());
			
		}
		 return keyPair;
	}
	
	public static void main(String args[]) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		RSAKeyPair.generatePublicPrivateKey();
	}
}
