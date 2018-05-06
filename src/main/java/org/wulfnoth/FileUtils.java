package org.wulfnoth;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author Young
 */
class FileUtils {

	static void cryptFile(Cipher cipher, InputStream in, OutputStream out)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] inBuffer = new byte[1024];
		int len;
		while ((len = in.read(inBuffer)) != -1) {
			byte[] outBuffer = cipher.update(inBuffer, 0, len);
			if ( outBuffer != null ) out.write(outBuffer);
		}
		byte[] finalBuffer = cipher.doFinal();
		if (finalBuffer != null) out.write(finalBuffer);
	}

}
