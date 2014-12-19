import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
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
	
	
	//	Variables
	public int _encSKSize;
	public byte[] _encSK;
	
	public int _signSize;
	public  byte[] _sResult;
	public String _signAlg;
	public  String _signProvider;
	
	public int _ivSize;
	public  byte[] _iv;
	
	public String _ksAlg;
	public String _ksProvider;
	
	public String _cipherAlg;
	public String _kgAlg;
	public String _kgProvider;
	
	public String _cipherKey;
	public String _cipherKeyProvider;
	
	public String _ksEncAlias;
	public String _ksDecAlias;
	
	

	public int get_encSKSize() {
		return _encSKSize;
	}

	public byte[] get_encSK() {
		return _encSK;
	}

	public int get_signSize() {
		return _signSize;
	}

	public byte[] get_sResult() {
		return _sResult;
	}

	public String get_signAlg() {
		return _signAlg;
	}

	public String get_signProvider() {
		return _signProvider;
	}

	public int get_ivSize() {
		return _ivSize;
	}

	public byte[] get_iv() {
		return _iv;
	}

	public String get_ksAlg() {
		return _ksAlg;
	}

	public String get_ksProvider() {
		return _ksProvider;
	}

	public String get_cipherAlg() {
		return _cipherAlg;
	}

	public String get_kgAlg() {
		return _kgAlg;
	}

	public String get_kgProvider() {
		return _kgProvider;
	}

	public String get_cipherKey() {
		return _cipherKey;
	}

	public String get_cipherKeyProvider() {
		return _cipherKeyProvider;
	}

	public String get_ksEncAlias() {
		return _ksEncAlias;
	}

	public String get_ksDecAlias() {
		return _ksDecAlias;
	}
	
	

	private void set_encSKSize(int _encSKSize) {
		this._encSKSize = _encSKSize;
	}

	private void set_encSK(byte[] _encSK) {
		this._encSK = _encSK;
	}

	private void set_signSize(int _signSize) {
		this._signSize = _signSize;
	}

	private void set_sResult(byte[] _sResult) {
		this._sResult = _sResult;
	}

	private void set_signAlg(String _signAlg) {
		this._signAlg = _signAlg;
	}

	private void set_signProvider(String _signProvider) {
		this._signProvider = _signProvider;
	}

	private void set_ivSize(int _ivSize) {
		this._ivSize = _ivSize;
	}

	private void set_iv(byte[] _iv) {
		this._iv = _iv;
	}

	private void set_ksAlg(String _ksAlg) {
		this._ksAlg = _ksAlg;
	}

	private void set_ksProvider(String _ksProvider) {
		this._ksProvider = _ksProvider;
	}

	private void set_cipherAlg(String _cipherAlg) {
		this._cipherAlg = _cipherAlg;
	}

	private void set_kgAlg(String _kgAlg) {
		this._kgAlg = _kgAlg;
	}

	private void set_kgProvider(String _kgProvider) {
		this._kgProvider = _kgProvider;
	}

	private void set_cipherKey(String _cipherKey) {
		this._cipherKey = _cipherKey;
	}

	private void set_cipherKeyProvider(String _cipherKeyProvider) {
		this._cipherKeyProvider = _cipherKeyProvider;
	}

	private void set_ksEncAlias(String _ksEncAlias) {
		this._ksEncAlias = _ksEncAlias;
	}

	private void set_ksDecAlias(String _ksDecAlias) {
		this._ksDecAlias = _ksDecAlias;
	}

	public Config(String path) throws Exception{
		
		BufferedReader in = null;
		String tLine;
	
		try {
			in = new BufferedReader(new FileReader(path));
			
			
			tLine  = in.readLine();
			_encSKSize = Integer.parseInt(in.readLine());
			_encSK = toByteArray (tLine, _encSKSize);
			
			tLine  = in.readLine();
			_signSize = Integer.parseInt(in.readLine());
			_sResult = toByteArray (tLine, _signSize);
			
			tLine  = in.readLine();
			_ivSize = Integer.parseInt(in.readLine());
			_iv = toByteArray (tLine, _ivSize);
			
			_ksAlg  = in.readLine();
			_ksProvider  = in.readLine();
			
			_cipherAlg  = in.readLine();
			_kgAlg  = in.readLine();
			_kgProvider  = in.readLine();
			
			_cipherKey = in.readLine();
			_cipherKeyProvider = in.readLine();

			_signAlg = in.readLine();
			_signProvider = in.readLine();
			
			_ksEncAlias = in.readLine();
			_ksDecAlias = in.readLine();
			
			
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally{
			if (in != null ) {
				in.close();
			}
		}
		
		
		
	}
	
	private byte[] toByteArray(String src, int size){
		
		String[] conv = src.replaceAll("[\\[\\]]", "").split(", ");
		byte[] cParam = new byte[size];
		for (int i = 0; i < conv.length; i++){
			cParam[i] = (byte)Integer.parseInt(conv[i]);
		}
		return cParam;
	}
	
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
