import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;


public class Config {
	// Configuration
	public final static String KS_ALG = "JCEKS";
	public final static String KS_PROVIDER = "SunJCE";
	public final static String KS_ENC_ALIAS = "encryptKeys";
	public final static String KS_DEC_ALIAS = "decryptKeys";
	
	public final static String KG_ALG = "AES";
	public final static String KG_PROVIDER = "SunJCE";

	public final static String IV_ALG = "SHA1PRNG";
	public final static byte IV_SIZE = 16;
	public final static String IV_PROVIDER  = "SUN";
	public final static String SIGN_ALG = "SHA1withRSA";
	public final static String SIGN_PROVIDER  ="SunRsaSign";
	
	public final static String CIPHER_ALG = "AES/CBC/PKCS5Padding";
	public final static String CIPHER_PROVIDER  ="SunJCE";
	
	public final static String CIPHER_KEY_ALG = "RSA";
	public final static String CIPHER_KEY_PROVIDER  ="SunJCE";
	
	public final static String ENCRYPTED_FILE_EXT  = ".enc";
	public final static String CONFIG_FILE_EXT  = ".conf";
	
	public final static int BLOCK_SIZE  = 1024;
	
	public static boolean GenerateConfigFile(String path, byte[] skCiphered, byte[] sResult, IvParameterSpec ivPS) throws Exception {
		BufferedWriter out = null;
		String fName = Utilites.GetFilePathWithoutExtension(path) + CONFIG_FILE_EXT;
		try{
			
			out = new BufferedWriter(new FileWriter(fName));
			
		    out.write(Arrays.toString(skCiphered) + "\r\n");
            out.write(skCiphered.length +"\r\n");
            out.write(Arrays.toString(sResult) + "\r\n");
            out.write(sResult.length + "\r\n");
            out.write(Arrays.toString(ivPS.getIV())+"\r\n");
            out.write(IV_SIZE+"\r\n");
            out.write(KS_ALG+"\r\n");
            out.write(KS_PROVIDER +"\r\n");
            out.write(CIPHER_ALG  + "\r\n");
            out.write(KG_ALG + "\r\n");
            out.write(KG_PROVIDER  + "\r\n");
            out.write(CIPHER_KEY_ALG +"\r\n");
            out.write(CIPHER_KEY_PROVIDER  +"\r\n");
            out.write(SIGN_ALG +"\r\n");
            out.write(SIGN_PROVIDER  +"\r\n");
            out.write(KS_ENC_ALIAS +"\r\n");
            out.write(KS_DEC_ALIAS +"\r\n");
			
			
		} catch (Exception e){
			return false;
			
		} finally {
			if (out != null){
				out.close();
			}
		}
		
		return true;
		
	}
}
