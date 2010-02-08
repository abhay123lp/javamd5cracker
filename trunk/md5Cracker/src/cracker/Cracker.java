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



/** Basic alogrithm description: 
 
 - Work-load distribution:
 An artifically selected (by the user) node is made aware of the hash and maximum lenght of the key. The amount of possible keys is calculated as maxNum.
 Other nodes connect to this leader by calling the giveMeWork() remote method.
 The leader maintains data structures (arrays, and lists) with the ips, and records of what work has been assigned to each node. Nodes are assigned ranges
 from within the maxNum, which they convert into key strings and verify in md5Cracker(). This is more efficient that passing around arrays of Strings. Also, given
 the 62 numeric base, and agreements on the baseDigits order, each key is uniquely identified by an integer.
 To keep track of what work has been assigned, it's essentially sufficient to subtract the chunkSize from the maxNum after each workAssignment. Complications 
 are implemented for liar detection and leader election.
 
 - Liar detection:
 Other than checking all the work given to nodes (hence re-doing all the work) detecting a liar is probabilistic (as opposed to guaranteed). Hence more than
 screening against malicious users, the algorithm verifies that clients are capable (know-how) to do the work expected of them.
 The probabilistic liar detection algorithm designed rests on uniquely identifying nodes, so as to distinguish liars from non-liars, (integrity) and on hiding some 
 information (concealment).
 Concealment is implemented by having only the artificial leader know the actual hash sought. When nodes ask for work they are given two hashes, one of which
 is a hash for which there is a key in the chunk of work assigned. Hence, if the node doesn't heureka at least once after being assigned work, then it means he lied.
 Assuming the node has no way to know which is the real hash, there should be a .5 probability of detecting a (malicious) liar. However, after the second work
 assignment, a malicious node could compare the previous hashes to the given ones and tell which is the target one, which is always passed. However this limitation
 applies only to small distributed systems, where the target hash is only one. Otherwise, several target hashes may be shuffled around nodes at each request, making
 it only a chance, that the same hash is sent to the same node repeatedly. Hence as the number of target hashes asymptotically increases the probability is maintained.
 This illustrates also that passing more fake hashes from within the range indeed increases the chances of detecting liars, to n-1/n. Notably the asymptotic complexity
 is not affected by the increase in n (# passed hashes) since n-1 of them would anyway be checked within the range of work assigned to the node. It's the heureka
 checking that actually makes a large n prohibitive (would cost as much as doing the work alone).
 
 Addittional steps (not implemented) would be to have the server check at random x/chunksize of the work done by the node, increasing the probability of detecting a
 liar by x/chunksize. Hence liar detection (even of malicious nodes) can be up to .5 + x/chunksize, which is reasonably high. Upon consideration it should be clear
 that the probability of detecting a liar through fake hashes, is much higher than the server randomly checking x of the passed keys. This is because it's already
 known that in maxNum-1 whether the node intends to lie or not is irrelevant.
 
 Identifying is done by giving each new node (that presents itself with client id of 0, as per the protocol) a unique id, and a unique 8-digits pin. This is done 
 so that a node may not be able to connect as another, other than by guessing the id and pin of that client. This doesn't prohibit a liar from presenting itself 
 again with an id 0, though.
 
 At last, a further liar detection enhancement (both in terms of concealment and integrity) is that artificially assign nodes credentials offline. That is, nodes
 cannot connect to the server without static password tokens. However this is not domain-specific, but is a general solution that rests on trusting the user that
 got the password.
 
 - Leader election:
 Leader election is done through a modification of the bully algorithm. A FIFO stack of connected ips is kept by the leader, and is broadcast (update) to all nodes 
 once they request work. Should a node fail to contact the artificial server, it'll contact the first in the stack. If that is it, then it will declare itself as the leader
 (initializing leader settings, if any, but not broadcasting).
 In a similar manner all those than contact that fail to contact the artificial server, will contact the first in the stack, which is identical for everyone.
 In the case a node had not yet declared itself as leader, but others have already appointed it and ask it for work, it will verify if it's leader is down,
 and if it really is his turn (which is always the case), before declaring itself.

Implementation notes:
 The following simplistic implementation choices have been made, acknwoledging the educational purposes of the project:
 -The primary reason for choosing RMI was to pratice what has been learned about it in class. It could be that other distributed architectures were better suited.
 -The leader election algorithm described above requires each node to be ready to become server at any point of time. This requires creating a registry, and
 having complete information about the overall task at all times. Also because most of development has been done on a single machine, at a single port only one 
 registry could be created. The simple workaround to this algorithmic requirement is to expect the should-become leader to be the first to discover the artificial
 server, finishing his chunk size first. Likewise, other clients would sleep 5 secs before connecting to it.
 Complete information also means that each node knows the target hash, which goes against the liar detection technique. This could be avoided by having the new leader
 first finish his job, but heureking to itself, and noticing which hashes key was not found. Clearly this doesn't increase the complexity of the algorithm, but 
 of the implementation, which was avoided here.
 
Testing:
 The distributed application has been successfully tested individually on a MacBook, and a MacBook Pro running Snow Leaopard, as well as jointly having the firewalls
 disabled, and the connection over ethernet. Keys of length 3, 4, and 5 were used.
 
**/

public class Cracker implements WorkAssigner {

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
	private static final int base = 62;
	private static final String baseDigits = "0Aa1BbCc2DdEe3FfGg4HhIi5JjKk6LlMm7NnOo8PpQq9RrSsTtUuVvWwXxYyZz"; //more ram less cpu
	private static final long serialVersionUID = -4650445096092405770L;
	private static int clientId, id;
	private static long pass;
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
	
	/** 
	* this makes sure all chunks that have not been accounted for are eventually re-assigned, to be completed.
	*/
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
			}
		}
	}
	/**
	* Used in leader election for recevery, to restart work not repeating committed work. Every node is made aware of this value, at each requestion for work.
	 **/
	private static void maxNumMaintenance(){
		guaranteedMaxNum = Math.max(maxUpperbound(), maxStack());
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
			System.exit(0); // mission complete!
		}
		if (compare(fakeHashes.get(clientId+1), key)){
			states[clientId+1] = heureked;
		}
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
	
	/**
	* giveMeWorkWithLiarDetec checks each client to see if it is a liar before it lets them get new work. Liars are defined as those who don't call heureka 
	* at least once before asking for new work. Once heureka is called twice, it means the hash is actually found the server quits.
	* all work  done by liars is redistributed by the Maintainer().
	*/
	@Override
	public Object[] giveMeWorkWithLiarDetec(int clientId, final String ip, long pass){
		int pos = clientId;
		
		if (clientId == 0){
			System.out.println("clientId is zero, and pass " + pass);
			passes[(pos = firstEmpty(states))] = (long) (Math.random()* 10000000); 
			System.out.println("Pos in states array " + pos + " and pass assigned is " + passes[pos]);
			states[pos] = heureked;
			pass = passes[pos];
			assert(!ips.contains(ip));
			ips.add(ip);
			clientId = pos;
			fakeHashes.add(null);
		}
		
		if (states[pos] != liar  && passes[pos] == pass){
			int numAssigned = maxNum;
			if (!stack.isEmpty()) numAssigned = stack.pop();
			else maxNum -= chunkSize;
			
			upperbound[pos] = numAssigned;
			final int iKey = upperbound[pos]-1; //(int) (numAssigned - chunkSize+Math.random()*10), would be an enhancement for random liar detection.
			final byte[] fakeHash = getHash(iKey);
			
			fakeHashes.add(pos,fakeHash);
			assert(Arrays.equals(fakeHashes.get(pos), fakeHash));
			time[pos] = System.currentTimeMillis();
			states[pos] = assigned;
						
			maxNumMaintenance();
			return new Object[]{Math.max(numAssigned - chunkSize, 0) , numAssigned, hash, fakeHash, maxKey, clientId, pass, ips};
		}
		System.out.println("Id  " + clientId +" and pass " + pass + "while states[pos] " + states[pos] + " and liar!");
		return null;	
	}
	 /**
	 *  converts from a base 10 to 62 ie 0-9 to a-z-A-Z-0-9.
	  Code adapted from http://javaconfessions.com/2008/09/convert-between-base-10-and-base-62-in_28.html.
	  
	 */
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
	 /**
	 //  is used to see if a hash is valid for checking if the final number is reached and also in liar detection.
	 */
	static boolean compare(final byte[] hash, final String key){
		final byte[] h, bs = key.getBytes();
		h = md.digest(bs);
		if (Arrays.equals(h,hash)) return true;
		return false;
	}
	 /**
	 //  checks a range of numbers to see if the key is in that range, and calls remote method heureka to suggest a finding.
	 */
	String md5Cracker(final byte[] hash, int i, int end, final WorkAssigner wa, final int maxKey, final byte[] fakeHash) throws RemoteException{
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
	
	
	
	private void work() throws Exception{
		// Get IP Address 
		while (true){
			Object[] work = null;
			try{
				System.out.println(" my id is " + id +  " my pass is  " + pass);
				work = ck.giveMeWorkWithLiarDetec(id, ip, pass);
				
				id = (Integer) work[5];
				pass = (Long) work[6];
				start = (Integer) work[0]; //don't panic if the server doesn't need you anymore and passed a null array.
				end = (Integer) work[1];
				maxKey = (Integer) work[4];
				ips = (LinkedList<String>) work[7];
				hash = (byte[]) work[2];
				md5Cracker(hash, start, end, ck, maxKey, (byte[]) work[3]);
				
				
			}catch (Exception eeeee) {				
				while(!ips.isEmpty() && work == null){
					try{
						work = ck.giveMeWorkWithLiarDetec(id, ip, pass);
						id = (Integer) work[5]; //don't panic if the server doesn't need you anymore and passed a null array.
						pass = (Long) work[6];
						start = (Integer) work[0]; 
						end = (Integer) work[1];
						maxKey = (Integer) work[4];
						ips = (LinkedList<String>) work[7];
						hash = (byte[]) work[2];
						md5Cracker(hash, start, end, ck, maxKey, (byte[]) work[3]);

						if(work!=null){
							break;
						}
					}
					catch(Exception e){
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
						}
						id = 0; pass = 0;
						
						do {
							Thread.sleep(5000);
							try{
								ck = (WorkAssigner) registry.lookup(WorkAssigner.class.getName());
								break;
							}catch (Exception eeeeeeeeee) {
							}
						} while (true);
						
					}
				}
			}
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
			final WorkAssigner cs = new Cracker(hash, maxKey);
			stub = (WorkAssigner) UnicastRemoteObject.exportObject(cs, port);
		}
		catch(Exception ee){
			registry.unbind(WorkAssigner.class.getName());
			final WorkAssigner cs = new Cracker(hash, maxKey);
			UnicastRemoteObject.exportObject(cs, port);
		}
		registry.rebind(WorkAssigner.class.getName(), stub);
		System.out.println(WorkAssigner.class.getName() + " bound");
		
		
	}
	
	public static void main(String[] args) throws Exception{
		
		final String host = (args != null && (args.length == 0 || args[0] == null))? null:args[0];
		port = (args != null && (args.length == 0 || args[1] == null))? Registry.REGISTRY_PORT:Integer.parseInt(args[1]);
		
		InetAddress address = InetAddress.getLocalHost();
		ip = address.getHostAddress();
		System.out.println(ip);
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
