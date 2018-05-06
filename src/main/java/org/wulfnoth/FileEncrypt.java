package org.wulfnoth;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;

/**
 * @author Young
 */
public class FileEncrypt {

	private Cipher cipher;

	public FileEncrypt(String keyPath) throws IOException {
		try(ObjectInputStream input = new ObjectInputStream(new FileInputStream(keyPath))) {
			Key key = null;
			Object obj = input.readObject();
			if (obj instanceof PrivateKey)
				key = (PrivateKey)obj;
			else if (obj instanceof PublicKey)
				key = (PublicKey)obj;
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (InvalidKeyException |
				NoSuchPaddingException |
				NoSuchAlgorithmException |
				ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	public File encrypt(String inputPath, String outputPath)
			throws IOException {
		File outFile = new File(outputPath);
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();

			byte[] iv = new byte[128/8];

			new SecureRandom().nextBytes(iv);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

			try (FileOutputStream out = new FileOutputStream(outFile)) {

				byte[] b = cipher.doFinal(secretKey.getEncoded());
				out.write(b);

				out.write(iv);

				Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
				ci.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
				try (FileInputStream in = new FileInputStream(inputPath)) {
					FileUtils.cryptFile(ci, in, out);
				}
			}
			return outFile;
		} catch (NoSuchPaddingException |
				InvalidKeyException |
				InvalidAlgorithmParameterException |
				IllegalBlockSizeException |
				BadPaddingException |
				NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return null;
	}

}
