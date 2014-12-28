import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Decrypter {
	
	
	//  ####  Variables  #####
	private final static int BUFFER_SIZE = 8;
	
	//  Inputs
	private static String _fPath;
	private static String _confPath;
	private static String _ksPath;
	private static String _ksEncPath;
	private static String _DecPath;
	private static String _storePass;
	private static String _keyPass;
	private static String _keyPassEnc;

	//	Configurations
	private static Config _InputConfig;
	
	
	//  ####  Objects  #####	
	
	//	Ciphers object
	private static Cipher _cipher;
	private static Cipher _cipherKey;
	
	//	KeyStores object
	private static KeyStore _ksDec;
	private static KeyStore _ksEnc;
	
	//	Signature object
	private static Signature _sign;
	
	//	Keys objects
	private static PrivateKey _privKey;
	private static PublicKey _pubKey;
	private static SecretKey _secKey;
	
	// 	####  MAIN FUNCTION  #####
	
	public static void main(String[] args) throws Exception {
		
		// Read and Validate Arguments
		if (!ReadUserInput(args, 8)){
			PrintError();
			return;
		}
		
		// Get Configurations from file
		try {
		_InputConfig = new Config(_confPath);
		} catch (Exception e){
			e.printStackTrace();
			PrintError();
			return;
		}

		// Generate all objects for decryption of data
		if (!GenerateVariablesFromConfig()) {
			PrintError();
			return;
		}
		
		// Decrypt Raw Data
		if (!DecryptDataFromFile(_fPath)){
			PrintError();
			return;
		}
		
		// Verify Data's signature is the same for the encryptor
		if (!SignCmp()) {
			PrintError();
			return;
		}
		
		System.out.println(Msg.SUCCESS_DECRYPT);
	}
	
	// 	####  FUNCTIONS  #####
	
	public static void PrintError(){
		System.out.println(Msg.FAIL_DECRYPT);
	}
	
	// Reads user input ( 	FilePath...
	// 						Configuration Path file...
	// 						Encryption and Decryption KeyStores...
	// 						Encryption private key...
	// 						Decryption private and public key
	//						Decryption file path
	private static boolean ReadUserInput(String[] args, int num) {

		if (args.length != num) {
			System.out.println(Msg.ERROR_SUFFINCENT_ARG);
			return false;
		}

		_fPath = args[0];
		_confPath = args[1];
		_ksPath = args[2];
		_ksEncPath = args[3];
		_keyPass = args[4];
		_storePass = args[5];
		_keyPassEnc = args[6];
		_DecPath = args[7];

		if (!Utilites.ExistFileMulti(new String[] { _fPath, _confPath, _ksPath, _ksEncPath })) {
			System.out.println(Msg.ERROR_INVALID_FILES_MSG);
			return false;
		}

		return true;
	}

	// Compares if Generated Signature is the same as is configuration file
	private static boolean SignCmp() throws IOException {

		FileInputStream sfs = null;
		
		try {
			sfs = new FileInputStream (_DecPath);
			int bytesRead = 0;
			byte[] readBuffer =  new byte[BUFFER_SIZE];
			
			//	Add bytes to the signature
			while (( bytesRead = sfs.read(readBuffer)) != -1 ) {
				_sign.update(readBuffer, 0, bytesRead);
			}
			
			//	Verification
			if (!_sign.verify(_InputConfig.get_sResult())){
				throw new Exception (Msg.SIGNATURE_MISMATCH_MSG);
			}
			
		} catch (Exception e){
			e.printStackTrace();
			BufferedWriter out = null;
			out = new BufferedWriter(new FileWriter(_DecPath));
			out.write(Msg.SIGNATURE_MISMATCH_MSG);
			out.close();
			
			return false;
			
		} finally { 
			if (sfs != null){
				sfs.close();
			}
		}
		
		return true;
	}

	//	Decrypting Data from encrypted path using initialized objects
	private static boolean DecryptDataFromFile(String path) throws IOException {
		
		byte[] buffer = new byte[BUFFER_SIZE];
		FileOutputStream fos = null;
		CipherInputStream cin = null;
		
		try{
		
			fos = new FileOutputStream(_DecPath);
			
			//	Decrypting Data
			cin = new CipherInputStream(new FileInputStream(path), _cipher);
			
			//	Iterating over block of bytes and saving to disk
			int bytesRead;
			while((bytesRead = cin.read(buffer)) != -1) {
				fos.write(buffer, 0, bytesRead);
			}
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			if (fos != null){
				fos.close();
			}
			if (cin != null){
				cin.close();
			}
		}
		
		return true;
		
	}

	//	Creating Objects from Config object. If fails, returns false and decryption fails.
	private static boolean GenerateVariablesFromConfig() {
		// TODO Auto-generated method stub
		
		try{
		
			//	Create Ciphers
		_cipher = Cipher.getInstance(_InputConfig.get_cipherAlg(), _InputConfig.get_kgProvider());
		_cipherKey =  Cipher.getInstance(_InputConfig.get_cipherKey(), _InputConfig.get_cipherKeyProvider());
		
			//		Create Signature
		_sign = Signature.getInstance(_InputConfig.get_signAlg(),_InputConfig.get_signProvider());

		
			//	Get KeyStores
		_ksDec = KeyStore.getInstance(_InputConfig.get_ksAlg(), _InputConfig.get_kgProvider());
		_ksDec = LoadKeyStoreToMemory(_ksPath, _keyPass);
		_ksEnc = LoadKeyStoreToMemory(_ksEncPath, _keyPassEnc);
		_ksEnc.getCertificate(_InputConfig.get_ksEncAlias());

		//		Obtain Decryptor private key
		_privKey = (PrivateKey) _ksDec.getKey(_InputConfig.get_ksDecAlias(), _storePass.toCharArray());
		
		//		Prepare Decryption for key
		_cipherKey.init(Cipher.DECRYPT_MODE, _privKey);
		_cipherKey.update(_InputConfig.get_encSK());
		
		//		Verify Signature using encrypter public signature
		_pubKey = _ksEnc.getCertificate(_InputConfig.get_ksEncAlias()).getPublicKey();
		_sign.initVerify(_pubKey);
		
		//		Decrypt Secret Key
		byte[] data = _cipherKey.doFinal();
		
		//		Create Symmetric key after decryption
		_secKey = new SecretKeySpec(data, _InputConfig.get_kgAlg());
		
		//		Init Decrypt data 
		_cipher.init(Cipher.DECRYPT_MODE, _secKey, new IvParameterSpec(_InputConfig.get_iv()));
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}

	// Load key store to memory based on jks path and password
	private static KeyStore LoadKeyStoreToMemory(String path, String pass) throws IOException {
		
		KeyStore ks = null;;	
		FileInputStream in = null;
		
		try {
			ks = KeyStore.getInstance(_InputConfig.get_ksAlg(), _InputConfig.get_kgProvider());
			in = new FileInputStream(path);
			ks.load(in, pass.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} finally {
			if (in != null){
				in.close();
			}
		}
		
		return ks;
		
	}

}
