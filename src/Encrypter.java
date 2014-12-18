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


public class Encrypter {


	
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

		

		
		if (!GenerateEncryptionData()) return;
		
		if (!SetCipher()) return;
		
		if (!EncryptDataToFile()) return;
		
		if (!SetEncryptedKey()) return;
		
		if (!Config.GenerateConfigFile(_fPath, _skCiphered, _sResult, _ivPS)) return;
		

		
		return;
		
	}
	
	
	private static boolean GenerateEncryptionData(){
		
		try {
			_ks = GetKeyStore( _ksPath, _keyPass);
			_ksDec = GetKeyStore( _ksPathDec, _keyPassDec);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		
		
		_sk = GenerateSecretKey();
		if (_sk == null) return false;
		
		_ivPS = GenerateIV();
		if (_ivPS == null) return false;
		
		_sign = GenerateSignature();
		if (_sign == null) return false;
		
		return true;
		
	}



	private static boolean SetEncryptedKey() {
		try {
			_cipherKey = Cipher.getInstance(Config.CIPHER_KEY_ALG, Config.CIPHER_KEY_PROVIDER);
			_cipherKey.init(Cipher.ENCRYPT_MODE, _ksDec.getCertificate(Config.KS_DEC_ALIAS));
			_cipherKey.update(_sk.getEncoded());
			
			_skCiphered = _cipherKey.doFinal();
			
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
		
	}
	


	private static boolean EncryptDataToFile() throws Exception {
		FileInputStream fi = null;
		FileOutputStream fo = null;
		String encPath = Utilites.GetFilePathWithoutExtension(_fPath) + Config.ENCRYPTED_FILE_EXT;
		
		int i;
		byte[] block = new byte[Config.BLOCK_SIZE];
		
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
			_cipher = Cipher.getInstance(Config.CIPHER_ALG, Config.CIPHER_PROVIDER);
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
			Signature sign = Signature.getInstance(Config.SIGN_ALG, Config.SIGN_PROVIDER);
			
			Key priv = _ks.getKey(Config.KS_ENC_ALIAS, _storePass.toCharArray());
			
			sign.initSign((PrivateKey) priv);
					
			return sign;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
	}

	private static IvParameterSpec GenerateIV() {
		byte[] iv = new byte[Config.IV_SIZE];
		SecureRandom secRand = null;
		try {
			secRand = SecureRandom.getInstance(Config.IV_ALG, Config.IV_PROVIDER);
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
			kg = KeyGenerator.getInstance(Config.KG_ALG, Config.KG_PROVIDER);
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
			ks = KeyStore.getInstance(Config.KS_ALG, Config.KS_PROVIDER);
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
