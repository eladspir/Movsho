import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Arrays;


import javax.crypto.spec.IvParameterSpec;

//	Class contains method to write and write from Configuration file.
//	The class stores data to be later used by decryption side
public class Config {

//	####  Local Variables  #####
	
	//	Key Stores
	public final String _ksAlg;
	public final String _ksProvider;
	public final String _ksEncAlias;
	public final String _ksDecAlias;
	

	//	Signature
	public final int _signSize;
	public final byte[] _signResult;
	public final String _signAlg;
	public final String _signProvider;
	
	//	IV
	public final int _ivSize;
	public final byte[] _iv;
	
	//	Encrypted Data Secret Key
	public final int _encSKSize;
	public final byte[] _encSK;
	public final String _cipherKey;
	public final String _cipherKeyProvider;

	//	Data Secret Key
	public final String _cipherAlg;
	public final String _kgAlg;
	public final String _kgProvider;
	

//	####  Constructor  #####
	
//	Reads and generates objects 
//	from given configuration file path.
	public Config(String path) throws Exception{
		
		BufferedReader in = null;
		String tLine;
	

		in = new BufferedReader(new FileReader(path));

		tLine  = in.readLine();
		_encSKSize = Integer.parseInt(in.readLine());
		_encSK = Utilites.toByteArray (tLine, _encSKSize);
	
		tLine  = in.readLine();
		_signSize = getNumberBufferedReader(in);
		_signResult = Utilites.toByteArray (tLine, _signSize);
	
		tLine  = in.readLine();
		_ivSize = getNumberBufferedReader(in);
		_iv = Utilites.toByteArray (tLine, _ivSize);
		
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
		
		
		if (in != null ) {
			in.close();
		}
		
	}
	
	//	Wrapping Read number from buffered reader
	private int getNumberBufferedReader(BufferedReader in) {
		int i;
		try {
			i =  Integer.parseInt(in.readLine());
		} catch (Exception e){
			i = 0;
		}
		return i;
	}


//	Generates Configuration file for encryption side
	public static boolean GenerateConfigFile(Encrypter.EncryptionDefaults DEFAULTS, String path, byte[] skCiphered, byte[] sResult, IvParameterSpec ivPS) throws Exception {
		BufferedWriter out = null;
		String fName = Utilites.GetFilePathWithoutExtension(path) + DEFAULTS.CONFIG_FILE_EXT;
		try{
			
			out = new BufferedWriter(new FileWriter(fName));
			
		    out.write(Arrays.toString(skCiphered) + "\r\n");
            out.write(skCiphered.length +"\r\n");
            out.write(Arrays.toString(sResult) + "\r\n");
            out.write(sResult.length + "\r\n");
            out.write(Arrays.toString(ivPS.getIV())+"\r\n");
            out.write(DEFAULTS.IV_SIZE+"\r\n");
            out.write(DEFAULTS.KS_ALG+"\r\n");
            out.write(DEFAULTS.KS_PROVIDER +"\r\n");
            out.write(DEFAULTS.CIPHER_ALG  + "\r\n");
            out.write(DEFAULTS.KG_ALG + "\r\n");
            out.write(DEFAULTS.KG_PROVIDER  + "\r\n");
            out.write(DEFAULTS.CIPHER_KEY_ALG +"\r\n");
            out.write(DEFAULTS.CIPHER_KEY_PROVIDER  +"\r\n");
            out.write(DEFAULTS.SIGN_ALG +"\r\n");
            out.write(DEFAULTS.SIGN_PROVIDER  +"\r\n");
            out.write(DEFAULTS.KS_ENC_ALIAS +"\r\n");
            out.write(DEFAULTS.KS_DEC_ALIAS +"\r\n");
			
			
		} catch (Exception e){
			return false;
			
		} finally {
			if (out != null){
				out.close();
			}
		}
		
		return true;
		
	}
	
//	####  Setters and Getters  #####
	
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
		return _signResult;
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
	
	
	
	
}
