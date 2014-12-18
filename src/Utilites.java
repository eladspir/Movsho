
public class Utilites {

	public static String GetFilePathWithoutExtension(String path){
		path = path.substring(0, path.lastIndexOf('.'));
		return path;
	}

	
}
