package cracker;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Cracker extends Remote{

	public Object[] giveMeWork() throws RemoteException;
	
}
