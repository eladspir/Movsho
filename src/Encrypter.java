import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class Encrypter {
	
	// 	####  Variables  #####
	
	// DEFAULTS
	public static class EncryptionDefaults {
		
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
	}
	
	// Input
	private static String _fPath;
	private static String _ksPath;
	private static String _ksPathDec;
	private static String _keyPass;
	private static String _keyPassDec;
	private static String _storePass;

	// Key Stores
	private static KeyStore _ks;
	private static KeyStore _ksDec;
	
	// Secret Key
	private static SecretKey _sk;
	private static byte[] _skCiphered;
	
	//	Signature
	private static Signature _sign;
	private static  byte[] _signResult;
	
	//Ciphers
	private static Cipher _cipher;
	private static Cipher _cipherKey;
	
	
	// IV Variables
	private static IvParameterSpec _ivPS = null;
	
	
	// 	####  MAIN FUNCTION  #####
	
	public static void main(String[] args) throws Exception {
			
		// Read and Validate Arguments
		if (!ReadUserInput(args, 6)) {
			PrintError();
			return;
		}
		
		// Generate Encryption Variables for raw data
		if (!GenerateEncryptionData()){
			PrintError();
			return;
		}
			
		// Encrypt raw data to file
		if (!EncryptDataToFile()) {
			PrintError();
			return;
		}
		
		// Encrypt Symmetric Key using Asymmetric encryption
		if (!SetEncryptedKey()) {
			PrintError();
			return;
		}
		
		// Save Configuration files
		if (!Config.GenerateConfigFile(new EncryptionDefaults() , _fPath, _skCiphered, _signResult, _ivPS)){
			PrintError();
			return;
		}
		
		System.out.println(Msg.SUCCESS_ENCRYPT);
		
		
	}
	
	// 	####  FUNCTIONS  #####
	
	public static void PrintError(){
		System.out.println(Msg.FAIL_ENCRYPT);
	}
	
//	Reads user input (	FilePath...
//							Encryption and Decryption KeyStores
//							Encryption private and public key
//							Decryption private and public key
	private static boolean ReadUserInput(String[] args, int num){
		
		
		if (args.length != num){
			System.out.println(Msg.ERROR_NOT_ENOUGH_ARG);
			
			return false;
		}
		
		_fPath = args[0];
		_ksPath = args[1];
		_ksPathDec = args[2];
		_keyPass = args[3];
		_storePass = args[4];
		_keyPassDec = args[5];
		
		if (!Utilites.ExistFileMulti(new String[] {_fPath, _ksPath, _ksPathDec})) {
			System.out.println(Msg.ERROR_INVALID_FILES_MSG);
			return false;
		}
		
		return true;
	}
	
	
//	Generates Encryption Data: 	KeyStores Objects, 
//								Secret Key, 
//								IV, 
//								Signature,
//								Cipher object
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
		
		if (!SetCipher()) return false;
		
		return true;
		
	}


//	Encrypting SecretKey
	private static boolean SetEncryptedKey() {
		try {
			_cipherKey = Cipher.getInstance(EncryptionDefaults.CIPHER_KEY_ALG, EncryptionDefaults.CIPHER_KEY_PROVIDER);
			_cipherKey.init(Cipher.ENCRYPT_MODE, _ksDec.getCertificate(EncryptionDefaults.KS_DEC_ALIAS));
			_cipherKey.update(_sk.getEncoded());
			
			_skCiphered = _cipherKey.doFinal();
			
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
		
	}
	

//	Encrypting Data (Including signing)
	private static boolean EncryptDataToFile() throws Exception {
		FileInputStream fi = null;
		FileOutputStream fo = null;
		String encPath = Utilites.GetFilePathWithoutExtension(_fPath) + EncryptionDefaults.ENCRYPTED_FILE_EXT;
		
		int i;
		byte[] block = new byte[EncryptionDefaults.BLOCK_SIZE];
		
		try {
			fi = new FileInputStream(new File(_fPath));
			fo = new FileOutputStream(new File(encPath));
			
			CipherOutputStream encryptedFile = new CipherOutputStream(fo, _cipher);
			while((i = fi.read(block))!=-1){
				encryptedFile.write(block, 0, i);
				_sign.update(block, 0, i);
			}
			
			_signResult = _sign.sign();
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

//	Creating Cipher for data
	private static boolean SetCipher() {

		try {
			_cipher = Cipher.getInstance(EncryptionDefaults.CIPHER_ALG, EncryptionDefaults.CIPHER_PROVIDER);
			_cipher.init(Cipher.ENCRYPT_MODE, _sk, _ivPS);
			return true;
			
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		
		
	}


//	Generate Encrypting Signature (Using private key)
	private static Signature GenerateSignature() {
		try {
			Signature sign = Signature.getInstance(EncryptionDefaults.SIGN_ALG, EncryptionDefaults.SIGN_PROVIDER);
			
			Key priv = _ks.getKey(EncryptionDefaults.KS_ENC_ALIAS, _storePass.toCharArray());
			
			sign.initSign((PrivateKey) priv);
					
			return sign;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
	}

//	Generating IV according to Default size	
	private static IvParameterSpec GenerateIV() {
		byte[] iv = new byte[EncryptionDefaults.IV_SIZE];
		SecureRandom secRand = null;
		try {
			secRand = SecureRandom.getInstance(EncryptionDefaults.IV_ALG, EncryptionDefaults.IV_PROVIDER);
			secRand.nextBytes(iv);
			
			return new IvParameterSpec(iv);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

//	Generating Symmetric Secret Key
	private static SecretKey GenerateSecretKey() {
		KeyGenerator kg = null;
		
		try {
			kg = KeyGenerator.getInstance(EncryptionDefaults.KG_ALG, EncryptionDefaults.KG_PROVIDER);
			return kg.generateKey();
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

//	Loading key store by jks path and corresponding private password
	private static KeyStore GetKeyStore( String path, String pass) throws IOException {
		KeyStore ks = null;
		FileInputStream ksInputStream = null;
		
		try {
			ks = KeyStore.getInstance(EncryptionDefaults.KS_ALG, EncryptionDefaults.KS_PROVIDER);
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
