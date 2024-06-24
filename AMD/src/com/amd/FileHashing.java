package com.amd;

/**
 * Application to generate SHA-256 hash of the attached file. 
 * No signing is needed. Just print hash in HEX encoding to standard output.
 */
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FileHashing {

	private String generateHexString(String fileName) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		try(InputStream is = getClass().getClassLoader().getResourceAsStream(fileName)){
			byte[] buf = new byte[1024];
			int read;
			while((read = is.read(buf))!=-1) {
				md.update(buf,0,read);
			}
		}
		StringBuffer sb = new StringBuffer();
		for(byte b : md.digest()) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
	
	public static void main(String args[]) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		FileHashing hex = new FileHashing();
		System.out.println(hex.generateHexString("AMD_image.jpg"));
		//Hex String : fa1bed1a61ca81be4d6ecbfe3a75523213a5e399b9db9dd74cfd65303d9c3cc4
	}
}
