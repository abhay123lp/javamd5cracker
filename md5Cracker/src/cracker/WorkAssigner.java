package cracker;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface WorkAssigner extends Remote{

	public Object[] giveMeWorkWithLiarDetec(int clientId, final String ip, long pass) throws RemoteException;
	public void heureka(final String key, final int clientId) throws RemoteException;
	
}
