package cracker;

import java.net.MalformedURLException;
import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;


public class CrackerServer implements Cracker {

	private static int maxNum, maxKey;
	private static  byte[] hash;
	private static final int chunkSize=1;

	private static int getSize(final int maxKey){
		int ret =0;
		for(int i=1; i<=maxKey; i++)
			ret+= Math.pow(CrackerClient.base, i);
		return ret;	
	}

	public Object[] giveMeWork(){
		Object[] ret = { maxNum-chunkSize, maxNum, hash, maxKey};
		maxNum -= chunkSize;
		System.out.println("Work from " + maxNum + " to " + maxNum + chunkSize + " has been assigned.");
		return ret;
	}

	//TODO: consider server.policy, as in wiki example 

	public static void main(String[] args) throws RemoteException, NoSuchAlgorithmException, NotBoundException, MalformedURLException, AlreadyBoundException{
		hash=args[0].getBytes();
		maxKey = Integer.parseInt(args[1]);
		maxNum = getSize(maxKey);

		final Cracker  cs = new CrackerServer(); //can this also be, final CrackerServer cs ? yes.
		final Cracker stub = (Cracker) UnicastRemoteObject.exportObject(cs, 0); //rmi chooses the port at run-time
		 Registry registry = null;
		try{
			 registry = LocateRegistry.createRegistry(1100);
		}
		catch (RemoteException e){
			//do nothing, error means registry already exists
			System.out.println("java RMI registry already exists.");
			registry = LocateRegistry.getRegistry();
		}

		registry.rebind(Cracker.class.getName(), stub);
		System.out.println(Cracker.class.getName() + " bound");

		if (Integer.parseInt(args[1])<4) CrackerClient.main(null); // optional

	}
}
