import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class Decrypter {
	
	private final static  String SIGNATURE_MISMATCH_MSG = "Error: Signatures mismatach. The proccess in not allowed.";

	// Variables
	private static String _fPath;
	private static String _DecPath;
	private static String _ksPath;
	private static String _ksEncPath;
	private static String _confPath;
	private static String _keyPass;
	private static String _keyPassEnc;
	private static String _storePass;
	private static Config _InputConfig;
	
	private static Cipher _cipher;
	private static Cipher _cipherKey;
	
	private static KeyStore _ksDec;
	private static KeyStore _ksEnc;
	private static Signature _sign;
	
	private static PrivateKey _privKey;
	private static PublicKey _pubKey;
	private static SecretKey _secKey;
	
	
	public static void main(String[] args) throws Exception {
		
		
		// TODO add function
		_fPath = args[0];
		_confPath = args[1];
		_ksPath = args[2];
		_ksEncPath = args[3];
		_keyPass = args[4];
		_storePass = args[5];
		_keyPassEnc = args[6];
		
		_InputConfig = new Config(_confPath);
		_DecPath = Utilites.GetFilePathWithoutExtension(_fPath) + ".dec";
		
		
		if (!GenerateVariablesFromConfig()) return;
		
		
		
		if (!DecryptDataFromFile(_fPath)) return;
		
		if (!SignCmp()) return;
		
		
	}


	private static boolean SignCmp() throws IOException {
		// TODO Auto-generated method stub
		
		FileInputStream sfs = null;
		try {
			sfs = new FileInputStream (_DecPath);
			int bytesRead = 0;
			byte[] readBuffer =  new byte[8];
			
			while (( bytesRead = sfs.read(readBuffer)) != -1 ) {
				_sign.update(readBuffer, 0, bytesRead);
			}
			
			if (!_sign.verify(_InputConfig.get_sResult())){
				throw new Exception (SIGNATURE_MISMATCH_MSG);
			}
		} catch (Exception e){
			e.printStackTrace();
			BufferedWriter out = null;
			out = new BufferedWriter(new FileWriter(_DecPath));
			out.write(SIGNATURE_MISMATCH_MSG);
			out.close();
			
			return false;
		} finally { 
			if (sfs != null){
				sfs.close();
			}
		}
		
		return true;
	}


	private static boolean DecryptDataFromFile(String path) throws IOException {
		// TODO Auto-generated method stub
		
		//TODO: why 8?
		byte[] buffer = new byte[8];
		FileOutputStream fos = null;
		CipherInputStream cin = null;
		
		try{
		
			
			fos = new FileOutputStream(_DecPath);
			cin = new CipherInputStream(new FileInputStream(path), _cipher);
			
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


	private static boolean GenerateVariablesFromConfig() {
		// TODO Auto-generated method stub
		
		try{
		
		_cipher = Cipher.getInstance(_InputConfig.get_cipherAlg(), _InputConfig.get_kgProvider());
		_cipherKey =  Cipher.getInstance(_InputConfig.get_cipherKey(), _InputConfig.get_cipherKeyProvider());
		_sign = Signature.getInstance(_InputConfig.get_signAlg(),_InputConfig.get_signProvider());
		_ksDec = KeyStore.getInstance(_InputConfig.get_ksAlg(), _InputConfig.get_kgProvider());
		
		_ksDec = LoadKeyStoreToMemory(_ksPath, _keyPass);
		_ksEnc = LoadKeyStoreToMemory(_ksEncPath, _keyPassEnc);
		
		
		_ksEnc.getCertificate(_InputConfig.get_ksEncAlias());

		
		_privKey = (PrivateKey) _ksDec.getKey(_InputConfig.get_ksDecAlias(), _storePass.toCharArray());
		_cipherKey.init(Cipher.DECRYPT_MODE, _privKey);
		_cipherKey.update(_InputConfig.get_encSK());
		
		_pubKey = _ksEnc.getCertificate(_InputConfig.get_ksEncAlias()).getPublicKey();
		_sign.initVerify(_pubKey);
		
		byte[] data = _cipherKey.doFinal();
		_secKey = new SecretKeySpec(data, _InputConfig.get_kgAlg());
		
		_cipher.init(Cipher.DECRYPT_MODE, _secKey, new IvParameterSpec(_InputConfig.get_iv()));
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}


	private static KeyStore LoadKeyStoreToMemory(String path, String pass) throws IOException {
		// TODO Auto-generated method stub
		
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
