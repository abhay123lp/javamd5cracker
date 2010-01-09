package cracker;

import java.net.MalformedURLException;
import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;


public class CrackerClientTest {

	private static void test(final String key) throws NoSuchAlgorithmException, RemoteException, MalformedURLException, NotBoundException, AlreadyBoundException{
		byte[] bs = key.getBytes();
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] h = md.digest(bs);
		String s = new String(h);
		String[] args = {s, String.valueOf(key.length())};
		CrackerServer.main(args);
		args[0] = "localhost";
		args[1] = "1100";
		CrackerClient.main(args);
	}
	
	@Test
	public void testMain() throws NoSuchAlgorithmException, RemoteException, NotBoundException, MalformedURLException, AlreadyBoundException {
		final String key = "0pen";
		test(key);
	}
	
	public static void main(String[] args) throws RemoteException, NoSuchAlgorithmException, NotBoundException, MalformedURLException, AlreadyBoundException{
		final String key = args[0];
		test(key);
	}

}
