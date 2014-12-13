import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;




public class Encoder {

	// Configuration
	private final static String KS_ALG = "JCEKS";
	private final static String KS_PROVIDER = "SunJCE";
	private final static String KS_ENC_ALIAS = "encryptKeys";
	private final static String KS_DEC_ALIAS = "decryptKeys";
	
	private final static String KG_ALG = "AES";
	private final static String KG_PROVIDER = "SunJCE";

	private final static String IV_ALG = "SHA1PRNG";
	private final static byte IV_SIZE = 16;
	private final static String IV_PROVIDER  = "SUN";
	private final static String SIGN_ALG = "SHA1withRSA";
	private final static String SIGN_PROVIDER  ="SunRsaSign";
	
	private final static String CIPHER_ALG = "AES/CBC/PKCS5Padding";
	private final static String CIPHER_PROVIDER  ="SunJCE";
	
	private final static String CIPHER_KEY_ALG = "RSA";
	private final static String CIPHER_KEY_PROVIDER  ="SunJCE";
	
	private final static String ENCRYPTED_FILE_EXT  = ".enc";
	private final static String CONFIG_FILE_EXT  = ".conf";
	
	private final static int BLOCK_SIZE  = 1024;
	
	// Variables
	private static String _fPath;
	private static String _ksPath;
	private static String _ksPathDec;
	private static String _keyPass;
	private static String _keyPassDec;
	private static String _storePass;

	private static KeyStore _ks;
	private static KeyStore _ksDec;
	private static SecretKey _sk;
	
	private static Signature _sign;
	private static Cipher _cipher;
	private static Cipher _cipherKey;
	
	private static byte[] _skCiphered;
	private static  byte[] _sResult;
	
	// IV Variables
	private static IvParameterSpec _ivPS = null;
	
	public static void main(String[] args) throws Exception {


		//TODO: assert if no arguments (READ ARGS)
		_fPath = args[0];
		_ksPath = args[1];
		_ksPathDec = args[2];
		_keyPass = args[3];
		_storePass = args[4];
		_keyPassDec = args[5];
		_ks = GetKeyStore( _ksPath, _keyPass);
		_ksDec = GetKeyStore( _ksPathDec, _keyPassDec);
		
		_sk = GenerateSecretKey();
		if (_sk == null) return;
		
		_ivPS = GenerateIV();
		if (_ivPS == null) return;
		
		_sign = GenerateSignature();
		if (_sign == null) return;
		
		if (!SetCipher()) return;
		
		if (!EncryptDataToFile()) return;
		
		if (!SetEncryptedKey()) return;
		
		if (!GenerateConfigFile()) return;
		

		
		return;
		
	}
	
	
	private static boolean GenerateConfigFile() throws Exception {
		BufferedWriter out = null;
		String fName = GetFilePathWithoutExtension(_fPath) + CONFIG_FILE_EXT;
		try{
			
			out = new BufferedWriter(new FileWriter(fName));
			
		    out.write(Arrays.toString(_skCiphered) + "\r\n");
            out.write(_skCiphered.length +"\r\n");
            out.write(Arrays.toString(_sResult) + "\r\n");
            out.write(_sResult.length + "\r\n");
            out.write(Arrays.toString(_ivPS.getIV())+"\r\n");
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


	private static boolean SetEncryptedKey() {
		try {
			_cipherKey = Cipher.getInstance(CIPHER_KEY_ALG, CIPHER_KEY_PROVIDER);
			_cipherKey.init(Cipher.ENCRYPT_MODE, _ksDec.getCertificate(KS_DEC_ALIAS));
			_cipherKey.update(_sk.getEncoded());
			
			_skCiphered = _cipherKey.doFinal();
			
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
		
	}
	
	private static String GetFilePathWithoutExtension(String path){
		path = path.substring(0, path.lastIndexOf('.'));
		return path;
	}


	private static boolean EncryptDataToFile() throws Exception {
		FileInputStream fi = null;
		FileOutputStream fo = null;
		String encPath = GetFilePathWithoutExtension(_fPath) + ENCRYPTED_FILE_EXT;
		
		int i;
		byte[] block = new byte[BLOCK_SIZE];
		
		try {
			fi = new FileInputStream(new File(_fPath));
			fo = new FileOutputStream(new File(encPath));
			
			CipherOutputStream encryptedFile = new CipherOutputStream(fo, _cipher);
			while((i = fi.read(block))!=-1){
				encryptedFile.write(block, 0, i);
				_sign.update(block, 0, i);
			}
			
			_sResult = _sign.sign();
			encryptedFile.close();


		} catch (Exception e) {

			e.printStackTrace();
			return false;
			
		} finally {
			if (fi != null){
				fi.close();
			}
			if (fo != null){
				fo.close();
			}

			
		}
		return true;
		
		
	}



	private static boolean SetCipher() {

		

		try {
			_cipher = Cipher.getInstance(CIPHER_ALG, CIPHER_PROVIDER);
			_cipher.init(Cipher.ENCRYPT_MODE, _sk, _ivPS);
			return true;
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

		
		
	}



	private static Signature GenerateSignature() {
		try {
			Signature sign = Signature.getInstance(SIGN_ALG, SIGN_PROVIDER);
			
			Key priv = _ks.getKey(KS_ENC_ALIAS, _storePass.toCharArray());
			
			sign.initSign((PrivateKey) priv);
					
			return sign;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
	}

	private static IvParameterSpec GenerateIV() {
		byte[] iv = new byte[IV_SIZE];
		SecureRandom secRand = null;
		try {
			secRand = SecureRandom.getInstance(IV_ALG, IV_PROVIDER);
			secRand.nextBytes(iv);
			
			return new IvParameterSpec(iv);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}


	private static SecretKey GenerateSecretKey() {
		KeyGenerator kg = null;
		
		try {
			kg = KeyGenerator.getInstance(KG_ALG, KG_PROVIDER);
			return kg.generateKey();
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private static KeyStore GetKeyStore( String path, String pass) throws IOException {
		KeyStore ks = null;
		FileInputStream ksInputStream = null;
		
		//	Loading key store from path
		try {
			ks = KeyStore.getInstance(KS_ALG, KS_PROVIDER);
			ksInputStream = new FileInputStream(path);
			ks.load(ksInputStream, pass.toCharArray());
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
			
		} finally {
			if (ksInputStream != null){
				ksInputStream.close();
			}
		}

		return ks;
	}
	

}
