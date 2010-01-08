package cracker;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CrackerClient {

	private static int start, end;
	static int base = 62;
	private static final String baseDigits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"; //more ram less cpu
	
	private static void heureka(final String iKey) throws NoSuchAlgorithmException{
		/*if ((s = md5Cracker(hash, iKey, iKey))!= null){*/
		System.out.println(iKey);
		System.exit(0);
		//}
	}
	
	private static String convert(int decimalNumber){
		String tempVal = decimalNumber == 0 ? "0" : "";  
		int mod = 0;  

		while( decimalNumber != 0 ) {  
			mod = decimalNumber % base;  
			tempVal = baseDigits.substring( mod, mod + 1 ) + tempVal;  
			decimalNumber = decimalNumber / base;  
		}  
		return tempVal;
	}
	
	static String md5Cracker(final byte[] hash, int i, int end, final int maxKey) throws java.security.NoSuchAlgorithmException{
		final MessageDigest md = MessageDigest.getInstance("MD5");
		String s;
		byte[] h,bs;
		for(;i< end; i++){
			s = convert(i);
			do{
				bs = s.getBytes();
				h = md.digest(bs);
				if (Arrays.equals(h,hash)) heureka(s);//should return iKey for part of liar detection
				else System.out.println("not " + s);
				s= 0+s;
			}while(s.length()<=maxKey);
		}
		return null;
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, RemoteException, NotBoundException{
		final Registry registry = LocateRegistry.getRegistry( (args == null || args.length == 0 )? "localhost" :args[0]); //name of server host
		final Cracker ck = (Cracker) registry.lookup(Cracker.class.getName());
		
		while (true){
			final Object[] work = ck.giveMeWork();
			start = (Integer) work[0];
			end = (Integer) work[1];
			final int maxKey = (Integer) work[3];
			md5Cracker((byte[]) work[2], start, end, maxKey);
		}
	}
}
