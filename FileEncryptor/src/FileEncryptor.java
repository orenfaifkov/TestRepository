import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class FileEncryptor 
{
	////////////////////////////////////////////////////////////////////////////
	// Defines
	////////////////////////////////////////////////////////////////////////////
	private static final String DEFAULT_INPUT_FILE_NAME = "Input.txt";
	private static final String PROPERTIES_OUTPUT_FILE_NAME = "EncryptOptions.xml";
	private static final String OUTPUT_FILE_NAME = "EncryptRes";
	
	private static final String ENCRYPTION_ALGO = "AES/CBC/PKCS5Padding";
	private static final String SIGNATURE_KEY_ALGO = "RSA";
	private static final String SIGNATURE_ALGO = "SHA1withRSA";
	private static final String IV_CREATION_ALGO = "SHA1PRNG";
	
	private static final String PROPERTY_DATA_LEN = "DataLen";
	private static final String PROPERTY_SIG_LEN = "SignatureLen";
	private static final String PROPERTY_ENCRYPTION_ALGO = "EncryptionAlgorithm";
	private static final String PROPERTY_SIGNATURE_ALGO = "SygnatureAlgorithm";
	private static final String PROPERTY_SIGNATURE_KEY_ALGO = "SygnatureKeyAlgorithm";
	private static final String PROPERTY_IV = "IV";
	private static final String PROPERTY_PUBLIC_KEY = "PublicKey";
	
	private static final String KEY_STORE_PASSWORD = "sideline";
	private static final String KEY_STORE_FILE_NAME = "KeyStore";
	private static final String ALIAS_AES_SECRET_KEY = "SecretKey";
	///////////////////////////////////////////////////////////////////////////// 
	
	/////////////////////////////////////////////////////////////////////////////
	// Private members
	/////////////////////////////////////////////////////////////////////////////
	private Properties m_Properties = new Properties();
	private KeyStore m_KeyStore;
	/////////////////////////////////////////////////////////////////////////////
	
	/////////////////////////////////////////////////////////////////////////////
	// Public functions
	/////////////////////////////////////////////////////////////////////////////
	/**
	 * @param args
	 */
	public static void main(String[] args) 
	{					
		FileEncryptor fileEncryptor = new FileEncryptor();
		
		// Initialize the encryptor
		if(!fileEncryptor.initialize())
		{
			System.out.println("Failed to initialize decryptor");
			return;
		}
				
		// Get the file name to get data for encryption from (Default value supplied if none is provided)
		String strInputFileName = DEFAULT_INPUT_FILE_NAME;
		if(args.length > 0 && !"".equals(args[0]))
		{
			strInputFileName = args[0];
		}
				
		// Sign & encrypt file
		if(!fileEncryptor.encryptFile(strInputFileName))
		{
			System.out.println("Failed to encrypt " + strInputFileName);
			return;
		}

		// Print results
		System.out.println("Encrypted " + strInputFileName); 
		System.out.println("Output file: " + OUTPUT_FILE_NAME);
		System.out.println("Encryption properties file: " + PROPERTIES_OUTPUT_FILE_NAME);
		System.out.println("Keystore file: " + KEY_STORE_FILE_NAME);
	}
	
	/**
	 * Initializes the encryptor
	 * @return
	 */
	public boolean initialize()
	{
		// Add Algos to configuration file
		addParamToProperties(PROPERTY_ENCRYPTION_ALGO, ENCRYPTION_ALGO);
		addParamToProperties(PROPERTY_SIGNATURE_ALGO, SIGNATURE_ALGO);
		addParamToProperties(PROPERTY_SIGNATURE_KEY_ALGO, SIGNATURE_KEY_ALGO);
			
		return initializeKeyStore();		
	}
	
	/**
	 * Sign & encrypt file
	 * @param strFileName
	 * @return True on sucess, false otherwise
	 */
	public boolean encryptFile(String strFileName)
	{
		// Get bytes for encryption
		byte[] bytesToEncrypt = readBytesFromFile(strFileName);
		
		if(bytesToEncrypt == null)
			return false;
		
		// Get Signature
		byte[] signature = sign(bytesToEncrypt);		
		
		if(signature == null)
			return false;
		
		// Add sig len to configuration file
		addParamToProperties(PROPERTY_SIG_LEN, String.valueOf(signature.length));
		
		// Get cipher
		Cipher cipher = getCipher();
		if(cipher == null || !initializeCipher(cipher))
			return false;
		
		try 
		{
			CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(OUTPUT_FILE_NAME), cipher);
			
			// Create one stream with data to encrypt concatenated with the signature
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write( bytesToEncrypt );
			outputStream.write( signature );
			
			// Add data len to configuration
			addParamToProperties(PROPERTY_DATA_LEN, String.valueOf(bytesToEncrypt.length));
			
			// Encrypt the stream
			cipherOutputStream.write(outputStream.toByteArray( ));
			
			// Flush to file & close
			cipherOutputStream.flush();			
			cipherOutputStream.close();
			
			// Flush key store & properties files
			if(flushKeyStore() && flushProperties())
				return true;
			
			return false;
		} 
		catch (FileNotFoundException e)
		{
			e.printStackTrace();
			return false;
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
			return false;
		}
	}
	
	///////////////////////////////////////////////////////////////
	// Private methods
	///////////////////////////////////////////////////////////////
	
	private boolean initializeKeyStore()
	{
		try 
		{
			m_KeyStore = KeyStore.getInstance("JCEKS");
			m_KeyStore.load(null, KEY_STORE_PASSWORD.toCharArray());
			return true;
		} 
		catch (KeyStoreException e) 
		{
			e.printStackTrace();
			return false;
		} 
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
			return false;
		} 
		catch (CertificateException e) 
		{
			e.printStackTrace();
			return false;
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
			return false;
		}
	}
	
	private Cipher getCipher()
	{	
		try 
		{
			Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGO);
			return cipher;
		} 
		catch (NoSuchAlgorithmException e) 
		{			
			e.printStackTrace();
			return null;
		} 
		catch (NoSuchPaddingException e) 
		{
			e.printStackTrace();
			return null;
		}
	}
	
	private boolean initializeCipher(Cipher cipher)
	{ 
		try
		{
			// Create IV
			SecureRandom secureRandom = SecureRandom.getInstance(IV_CREATION_ALGO);
			
			byte[] ivBytes = new byte[16];
			secureRandom.nextBytes(ivBytes);		
			IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
			
			// Save to properties
			addParamToProperties(PROPERTY_IV, Base64.encodeBytes(ivParameterSpec.getIV()));			
			
			// create Key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			SecretKey secretKey = keyGenerator.generateKey();
			
			// Save to key store
			m_KeyStore.setEntry(ALIAS_AES_SECRET_KEY, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));
			
			// Initialize cipher
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
			
			return true;
			
		} 
		catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
			return false;
		} 
		catch (InvalidKeyException e) 
		{
			e.printStackTrace();
			return false;
		} 
		catch (InvalidAlgorithmParameterException e) 
		{
			e.printStackTrace();
			return false;
		} 
		catch (KeyStoreException e) 
		{
			e.printStackTrace();
			return false;
		}		
	}
	
	private byte[] readBytesFromFile(String strFileName)
	{
		File file = new File(strFileName);
	    byte []buffer = new byte[(int) file.length()];
	    
	    InputStream ios = null;
	    try 
	    {
	        ios = new FileInputStream(file);
	        if ( ios.read(buffer) == -1 ) 
	        {
	            return null;
	        } 
	        
	    } 
	    catch (FileNotFoundException e) 
	    {
			e.printStackTrace();
			return null;
		} 
	    catch (IOException e) 
		{
			e.printStackTrace();
			return null;
		} 
	    finally 
	    { 
	        try 
	        {
	             if ( ios != null ) 
	                  ios.close();
	        }
	        catch ( IOException e) 
	        {
	        	return null;
	        }
	    }

	    return buffer;
	}
	
	private byte[] sign(byte[] bytes)
	{
		try 
		{
			// Generate key pair
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(SIGNATURE_KEY_ALGO);
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			
			// Get private key
			PrivateKey privateKey = keyPair.getPrivate();
			
			// Initialize signature with key
			Signature signature = Signature.getInstance(SIGNATURE_ALGO);
			signature.initSign(privateKey);
			
			// Get public key and save to properties
			PublicKey publicKey = keyPair.getPublic();
			
			addParamToProperties(PROPERTY_PUBLIC_KEY, Base64.encodeBytes(publicKey.getEncoded()));			
			
			// Update signature
			signature.update(bytes);
			
			return signature.sign();						
		} 
		catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
			return null;
		} 
		catch (InvalidKeyException e) 
		{
			e.printStackTrace();
			return null;
		} catch (SignatureException e) 
		{
			e.printStackTrace();
			return null;
		}
	}
	
	
	private void addParamToProperties(Object objKey, Object objValue)
	{
		m_Properties.put(objKey, objValue);
	}
	
	
	private boolean flushKeyStore()
	{
		try 
		{
			m_KeyStore.store(new FileOutputStream(KEY_STORE_FILE_NAME), KEY_STORE_PASSWORD.toCharArray());
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	
	private boolean flushProperties()
	{
		try 
		{
			FileOutputStream fileOutputSteam = new FileOutputStream(PROPERTIES_OUTPUT_FILE_NAME);
			m_Properties.storeToXML(fileOutputSteam, "Ecryption properties");
			return true;
		} 
		catch (FileNotFoundException e) 
		{
			e.printStackTrace();
			return false;
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
			return false;
		}
	}
}
