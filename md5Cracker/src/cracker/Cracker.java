package cracker;

import java.net.InetAddress;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;

public class Cracker implements WorkAssigner {

	private static String test = new String();



	private static int maxNum; 
	private int maxKey;
	private byte[] hash;
	private static final int clientsSize = 1000;
	private static final long[] passes = new long[clientsSize];
	private static final int[] upperbound = new int[clientsSize];
	private static ArrayList<byte[]> fakeHashes = new ArrayList<byte[]>();
	private static final int[] states = new int[clientsSize];
	private static final long[] time = new long[clientsSize];
	private static final int chunkSize=1000; //must be power of 10 for random
	private static final int assigned = 1;
	private static final int liar = 3;
	private static final int heureked = 2;
	private static final LinkedList<Integer> stack = new LinkedList<Integer>(); // look for stack
	private static  MessageDigest md;
	private static int start, end;
	static int base = 62;
	private static final String baseDigits = "0Aa1BbCc2DdEe3FfGg4HhIi5JjKk6LlMm7NnOo8PpQq9RrSsTtUuVvWwXxYyZz"; //more ram less cpu
	private static final long serialVersionUID = -4650445096092405770L;
	private static int clientId, id;
	private static long pass;
	//private static int returnedWorkTimes = 0;
	private static LinkedList<String> ips = new LinkedList<String>();
	private static int guaranteedMaxNum = maxNum;
	private static WorkAssigner ck; 
	private static String ip; 
	private static Registry registry;
	private static int port;

	public Cracker(final byte[] hash, final int maxKey){
		this.hash = hash;
		this.maxKey = maxKey;
	}

	public Cracker(){

	}

	private static class Maintainer extends Thread{
		private static long interval = 1000*60;
		@Override
		public void run(){
			while(true){
				try {
					sleep(interval);	
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				for (int i=0; i<time.length; i++)
					if (time[i] > interval){
						stack.push(upperbound[i]);
						time[i] = 0;
					}
				guaranteedMaxNum = Math.max(maxUpperbound(), maxStack());
			}
		}
	}

	private static int getSize(final int maxKey){
		int ret =0;
		for(int i=1; i<=maxKey; i++)
			ret+= Math.pow(base, i);
		return ret;	
	}

	// only in the leader
	public void heureka(final String key, final int clientId){
		if (compare(hash, key)){
			System.out.println(key);
			System.exit(0); // should actually quit the server.
		}
		if (compare(fakeHashes.get(clientId), key)) states[clientId] = heureked;
		else states[clientId] = liar;
	}

	private int firstEmpty(final int[] array){
		for (int i=1; i<array.length; i++) if (array[i] == 0) return i;
		throw new RuntimeException("no empty.");
	}

	private static int maxStack(){
		int max = 0; 
		if (!stack.isEmpty()) max = stack.getLast();
		for (Integer i: stack) if (i > max) max = i;
		return max;
	}

	private static int maxUpperbound(){
		int max = 0; 
		for (int i: upperbound) if (i > max) max = i;
		return max;
	}

	@Override
	public Object[] giveMeWorkWithLiarDetec(int clientId, final String ip, long pass){
		int pos = clientId;
		System.out.println("pass " + pass);
		if (clientId == 0){
			System.out.println("clientId is zero, and pass " + pass);
			passes[(pos = firstEmpty(states))] = (long) (Math.random()* 10000000); 
			System.out.println("Pos in states array " + pos + " and pass assigned is " + passes[pos]);
			states[pos] = heureked;
			pass = passes[pos];
			//returnedWorkTimes--; // to offset the counting for first time clients
			assert(!ips.contains(ip));
			ips.add(ip);
			clientId = pos;
			System.out.println("Now it is " + clientId);
		}
		if (states[pos] != liar && passes[pos] == pass){
			int numAssigned = maxNum;
			if (!stack.isEmpty()) numAssigned = stack.pop();
			else maxNum -= chunkSize;

			upperbound[pos] = numAssigned;
			final byte[] fakeHash = getHash((int) Math.max(0, (numAssigned - chunkSize/Math.random()*10)));

			fakeHashes.add(fakeHash); //should be in pos but
			assert(Arrays.equals(fakeHashes.get(pos), fakeHash));
			time[pos] = System.currentTimeMillis();
			states[pos] = assigned;

			//returnedWorkTimes++; //
			System.out.println(" the hash I'm giving are: " + hash + "  "  + fakeHash);
			return new Object[]{Math.max(numAssigned - chunkSize, 0) , numAssigned, hash, fakeHash, maxKey, clientId, pass, ips};
		}
		System.out.println("Id  " + clientId +" and pass " + pass + "while states[pos] " + states[pos] );
		return null;	
	}

	public static String convert(int decimalNumber){
		String tempVal = decimalNumber == 0 ? "0" : "";  
		int mod = 0;  

		while( decimalNumber != 0 ) {  
			mod = decimalNumber % base;  
			tempVal = baseDigits.substring( mod, mod + 1 ) + tempVal;  
			decimalNumber = decimalNumber / base;  
		}  
		return tempVal;
	}

	static boolean compare(final byte[] hash, final String key){
		final byte[] h, bs = key.getBytes();
		h = md.digest(bs);
		if (Arrays.equals(h,hash)) return true;
		return false;
	}

	String md5Cracker(final byte[] hash, int i, int end, final WorkAssigner wa, final int maxKey, final byte[] fakeHash) throws RemoteException{
		System.out.println( "The hash i got was " + new String(hash) + " while the fake " + fakeHash);
		MessageDigest md = null;
		try{
			md = MessageDigest.getInstance("MD5");
		}
		catch (java.security.NoSuchAlgorithmException e){
			e.printStackTrace();
			System.exit(-1);
		}
		String s;
		byte[] h,bs;
		for(;i< end; i++){
			s = convert(i);
			do{
				bs = s.getBytes();
				h = md.digest(bs);
				if (Arrays.equals(h,fakeHash) || Arrays.equals(h, hash)){
					if ( Arrays.equals(h,fakeHash) ) this.hash = fakeHash;
					else this.hash = hash;
					System.out.println("I've heureked.");
					wa.heureka(s, clientId );//should return iKey for part of liar detection
				}
				else System.out.println("not " + s);
				s= 0+s;
			} while(s.length()<=maxKey);
		}
		return null;
	}

	private static byte[] getHash(final int iKey){
		try{
			md = MessageDigest.getInstance("MD5");
		}
		catch(java.security.NoSuchAlgorithmException e){
			e.printStackTrace();
			System.exit(-1);
		}
		return md.digest(convert(iKey).getBytes());
	}
	/*
	public Object[] giveMeWork(final CrackerClient cc){
		Object[] ret = { Math.max(0, maxNum-chunkSize), maxNum, hash, maxKey};
		maxNum -= chunkSize;		
		System.out.println("Work from " + Math.max(0, maxNum) + " to " + maxNum + chunkSize + " has been assigned.");
		return ret;
	}
	 */
	public Object[] giveMeWork(){
		Object[] ret = { Math.max(0, maxNum-chunkSize), maxNum, hash, maxKey};
		maxNum -= chunkSize;		
		System.out.println("Work from " + Math.max(0, maxNum) + " to " + maxNum + chunkSize + " has been assigned.");
		return ret;
	}

	//TODO: consider server.policy, as in wiki example 

	private void work() throws Exception{
		// Get IP Address 
		while (true){
			Object[] work = null;
			try{
				work = ck.giveMeWorkWithLiarDetec(id, ip, pass);
			}catch (Exception eeeee) {
				System.out.println(" Im  at 217 ");

				while(!ips.isEmpty() && work == null){
					System.out.println(" Im  at 219");
					try{
						System.out.println(" Im  at 230");
						work = ck.giveMeWorkWithLiarDetec(id, ip, pass);
						System.out.println(work);
						if(work!=null){
							break;
						}
					}
					catch(Exception e){
						System.out.println("caught excpetion e " + e);

						System.out.println("id " + id + " ip " + ip.toString());

						ips.pollLast();
						final String newIp = ips.peekLast();
						System.out.println(newIp);
						System.out.println(ip);
						if (ip.equals(newIp) && id == 1){
							System.out.println("I'm trying to become the new server with ip " + ip + ":"+ port + " hash : "  + hash + " and maxKey " + maxKey);

							Cracker.main(new String[]{ip, Integer.toString(port), new String(hash), Integer.toString(maxKey)});
							return;
						}
						else {
							System.out.println("I'm trying to connect to the new server " + ips.peekLast());
							registry = LocateRegistry.getRegistry(new String(ips.peekLast()), port); //name of server host
							System.out.println(registry);
						}
						id = 0; pass = 0;
						Thread.sleep(5000);
						ck = (WorkAssigner) registry.lookup(WorkAssigner.class.getName());
					}
				}
				System.out.println("id " + id + " ip " + new String(ip) + " my ip " + test);

			}
			id = (Integer) work[5];
			pass = (Long) work[6];
			start = (Integer) work[0]; //don't panic if the server doesn't need you anymore and passed a null array.
			end = (Integer) work[1];
			maxKey = (Integer) work[4];
			ips = (LinkedList<String>) work[7];
			hash = (byte[]) work[2];
			System.out.println("my hash " + this.hash);
			md5Cracker(hash, start, end, ck, maxKey, (byte[]) work[3]);
		}
	}

	/*
	 * args: hostname, port, if server: hash, maxKey
	 */


	private void becomeServer(final byte[] hash, final int maxKey) throws Exception{
		this.hash = hash;
		System.out.println(" the hash I got is " + new String(hash));
		this.maxKey = maxKey;
		try{
			registry = LocateRegistry.createRegistry(port);
		}
		catch(RemoteException e){
			registry = LocateRegistry.getRegistry();
		}
		System.out.println("I've a registry.");
		WorkAssigner stub = null;
		try{
			WorkAssigner cs = new Cracker(hash, maxKey); //can this also be, final CrackerServer cs ? yes.
			stub = (WorkAssigner) UnicastRemoteObject.exportObject(cs, port); //rmi chooses the port at run-time
		}
		catch(Exception ee){
			registry.unbind(WorkAssigner.class.getName());
			WorkAssigner cs = new Cracker(hash, maxKey); //can this also be, final CrackerServer cs ? yes.
			UnicastRemoteObject.exportObject(cs, port); //rmi chooses the port at run-time
		}
		registry.rebind(WorkAssigner.class.getName(), stub);// was stub
		System.out.println(WorkAssigner.class.getName() + " bound");


		//if (maxKey<4) md5Cracker(hash,0,maxNum,stub, maxKey, hash); // optional, stub?
	}

	public static void main(String[] args) throws Exception{

		final String host = (args != null && (args.length == 0 || args[0] == null))? null:args[0];
		port = (args != null && (args.length == 0 || args[1] == null))? Registry.REGISTRY_PORT:Integer.parseInt(args[1]);

		InetAddress address = InetAddress.getLocalHost();
		ip = address.getHostAddress();
		System.out.println(ip);
		test = ip;
		final Cracker  cs = new Cracker();
		if(args != null && args.length > 2 && args[2] != null){

			maxNum = getSize(Integer.parseInt(args[3]));
			new Maintainer();
			ips.add(ip); //I'm the bull boss.

			cs.becomeServer(args[2].getBytes(), Integer.parseInt(args[3]));
		}
		else{
			registry = LocateRegistry.getRegistry(host, port); //name of server host
			ck = (WorkAssigner) registry.lookup(WorkAssigner.class.getName());
			cs.work();
		}
	}
}
