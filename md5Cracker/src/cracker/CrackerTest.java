package cracker;

import java.security.MessageDigest;

public class CrackerTest {

	private static void test(final String key) throws Exception{
		byte[] bs = key.getBytes();
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] h = md.digest(bs);
		String s = new String(h);
		String[] args = {"localhost ", "1099", s, String.valueOf(key.length())};
		Cracker.main(args);
		args[0] = "localhost";
			
		args[1] = "1099";
		args[2] = null; args[3] = null;
		Cracker.main(args);
	}
	
	public static void main(String[] args) throws Exception{
		final String key = args[0];
		test(key);
	}
}
