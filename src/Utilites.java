import java.io.File;

public class Utilites {
	

	public static String GetFilePathWithoutExtension(String path){
		path = path.substring(0, path.lastIndexOf('.'));
		return path;
	}
	
	public static boolean ExistFile(String path){
		return new File(path).isFile();
	}
	
	public static boolean ExistFileMulti(String[] paths){
		for ( String path : paths) {
			if (!ExistFile(path)){		
				return false;
			}
				
		}
		return true;
	}
	
	static byte[] toByteArray(String src, int size){
		
		String[] conv = src.replaceAll("[\\[\\]]", "").split(", ");
		byte[] cParam = new byte[size];
		for (int i = 0; i < conv.length; i++){
			cParam[i] = (byte)Integer.parseInt(conv[i]);
		}
		return cParam;
	}

	
}
