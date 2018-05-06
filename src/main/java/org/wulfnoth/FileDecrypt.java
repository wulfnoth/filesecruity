package org.wulfnoth;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.*;

/**
 * @author Young
 */
public class FileDecrypt {

	private Cipher cipher;

	public FileDecrypt(String keyPath) throws IOException {

		try(ObjectInputStream input = new ObjectInputStream(new FileInputStream(keyPath))) {
			Key key = null;
			Object obj = input.readObject();
			if (obj instanceof PrivateKey)
				key = (PrivateKey)obj;
			else if (obj instanceof PublicKey)
				key = (PublicKey)obj;

			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);
		} catch (InvalidKeyException |
				NoSuchPaddingException |
				NoSuchAlgorithmException |
				ClassNotFoundException e) {
			e.printStackTrace();
		}

	}

	public void decrypt(String inputPath, String outputPath)
			throws IOException {

		try (FileInputStream in = new FileInputStream(inputPath)) {

			byte[] b = new byte[256];
			in.read(b);
			byte[] keyBuffer = cipher.doFinal(b);
			SecretKeySpec spec = new SecretKeySpec(keyBuffer, "AES");


			byte[] iv = new byte[128/8];
			in.read(iv);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, spec, ivParameterSpec);

			try (FileOutputStream out = new FileOutputStream(outputPath)){
				FileUtils.cryptFile(ci, in, out);
			}
		} catch (NoSuchAlgorithmException |
				InvalidKeyException |
				InvalidAlgorithmParameterException |
				NoSuchPaddingException |
				BadPaddingException |
				IllegalBlockSizeException e) {
			e.printStackTrace();
		}
	}

}
