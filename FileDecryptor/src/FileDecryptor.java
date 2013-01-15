import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class FileDecryptor 
{
	/////////////////////////////////////////////////////////////////////
	// Defines
	/////////////////////////////////////////////////////////////////////
	private static final String DEFAULT_INPUT_FILE_NAME = "EncryptRes";
	private static final String PROPERTIES_INPUT_FILE_NAME = "EncryptOptions.xml";
	private static final String OUTPUT_FILE_NAME = "DecryptRes.txt";
	
	private static final String PROPERTY_DATA_LEN = "DataLen";
	private static final String PROPERTY_ENCRYPTION_ALGO = "EncryptionAlgorithm";
	private static final String PROPERTY_SIGNATURE_ALGO = "SygnatureAlgorithm";
	private static final String PROPERTY_SIGNATURE_KEY_ALGO = "SygnatureKeyAlgorithm";
	private static final String PROPERTY_SIG_LEN = "SignatureLen";
	private static final String PROPERTY_IV = "IV";
	private static final String PROPERTY_PUBLIC_KEY = "PublicKey";
	
	private static final String KEY_STORE_FILE_NAME = "KeyStore";
	private static final String ALIAS_AES_SECRET_KEY = "SecretKey";
	//////////////////////////////////////////////////////////////////////
	 
	/////////////////////////////////////////////////////////////////////
	// Members
	/////////////////////////////////////////////////////////////////////
	private Properties m_Properties = new Properties();
	private KeyStore m_KeyStore;
	
	private String m_strEncryptionAlgo = "";
	private String m_strSignatureAlgo = "";
	private String m_strSignatureKeyAlgo = "";
	private int m_iDataLen = 0;
	private int m_iSignatureLen = 0;
	
	private IvParameterSpec m_ivParameterSpec = null;
	private PublicKey m_PublicKey = null;
	private SecretKey m_SecretKey = null;
	private static String m_strPassword = "";
	//////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////////////////////////////////
	// Public methods
	//////////////////////////////////////////////////////////////////////
	/**
	 * @param args
	 */
	public static void main(String[] args) 
	{						
		FileDecryptor fileDecryptor = new FileDecryptor();
		
		// Get password from program param
		if(args.length > 0 && !"".equals(args[0]))
		{
			m_strPassword = args[0];
		}
		else
		{
			System.out.println("Password must be supplied!"); 
		}
		
		// Initialize the decryptor
		if(!fileDecryptor.initialize())
		{
			System.out.println("Failed to initialize decryptor");
			return;
		}
				
		// Validate signature & decrypt if siganture is valid
		if(!fileDecryptor.decryptFile())
		{
			System.out.println("Failed to decrypt " + DEFAULT_INPUT_FILE_NAME);
			return;
		}

		// Print resutls
		System.out.println("Encrypted " + DEFAULT_INPUT_FILE_NAME); 
		System.out.println("Output file: " + OUTPUT_FILE_NAME);
	}
	
	
	/**
	 * Initialize the decryptor.
	 * Params are fetched from properties file.
	 * Keys fetched from keystore file
	 * @return True if succesful, False otherwise
	 */
	public boolean initialize()
	{
		try 
		{
			// Get properties from file
			m_Properties.loadFromXML(new FileInputStream(PROPERTIES_INPUT_FILE_NAME));
			m_iDataLen = Integer.valueOf(m_Properties.getProperty(PROPERTY_DATA_LEN));
			m_iSignatureLen = Integer.valueOf(m_Properties.getProperty(PROPERTY_SIG_LEN));
			m_strEncryptionAlgo = m_Properties.getProperty(PROPERTY_ENCRYPTION_ALGO);
			m_strSignatureAlgo = m_Properties.getProperty(PROPERTY_SIGNATURE_ALGO);
			m_strSignatureKeyAlgo = m_Properties.getProperty(PROPERTY_SIGNATURE_KEY_ALGO);
			m_ivParameterSpec = new IvParameterSpec(Base64.decode(m_Properties.getProperty(PROPERTY_IV)));	
			m_PublicKey = KeyFactory.getInstance(m_strSignatureKeyAlgo).generatePublic(new X509EncodedKeySpec(Base64.decode(m_Properties.getProperty(PROPERTY_PUBLIC_KEY))));
			
			// Get key store alias's from file
			m_KeyStore = KeyStore.getInstance("JCEKS");
			m_KeyStore.load(new FileInputStream(KEY_STORE_FILE_NAME), m_strPassword.toCharArray());
			KeyStore.SecretKeyEntry secretKeyEntry = (SecretKeyEntry) m_KeyStore.getEntry(ALIAS_AES_SECRET_KEY, new KeyStore.PasswordProtection(m_strPassword.toCharArray()));
			m_SecretKey = secretKeyEntry.getSecretKey();
			
			return true;
		} catch (InvalidPropertiesFormatException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e)
		{
			e.printStackTrace();
		}
	
		return false;
	}
	
	/**
	 * Decrypt file if signature is valid
	 * @return True if successful, False otherwise
	 */
	public boolean decryptFile()
	{				
		// Get cipher
		Cipher cipher = getCipher();
		if(cipher == null || !initializeCipher(cipher))
			return false;
		
		try 
		{
			// Open decrypted file
			File decFile = new File(DEFAULT_INPUT_FILE_NAME);
			CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(decFile), cipher);
			
			// Decrypt data & signature bytes
			byte[] DecryptDataBytes = new byte[m_iDataLen];
			byte[] SignatureDataBytes = new byte[m_iSignatureLen];
			
			int iBytesRead = 0;
			
			// Decrypt data
			while (iBytesRead != -1 && iBytesRead != DecryptDataBytes.length)
			{
			  iBytesRead += cipherInputStream.read(DecryptDataBytes, iBytesRead, DecryptDataBytes.length);
			}
			
			iBytesRead = 0;
			
			// Decrypt signature
			while (iBytesRead != -1 && iBytesRead != SignatureDataBytes.length)
			{
			  iBytesRead += cipherInputStream.read(SignatureDataBytes, iBytesRead, SignatureDataBytes.length);
			}
			
			cipherInputStream.close();
			
			// Validate signature match data
			if(!validateSignature(DecryptDataBytes, SignatureDataBytes))
				return false;
			
			// Write decrypted data to result file if signature match
			FileOutputStream fileOutPutStream = new FileOutputStream(OUTPUT_FILE_NAME);
			fileOutPutStream.write(DecryptDataBytes);
			fileOutPutStream.close();
						
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
	
	/////////////////////////////////////////////////////////////////
	// Private methods
	/////////////////////////////////////////////////////////////////
	
	private Cipher getCipher()
	{	
		try 
		{
			Cipher cipher = Cipher.getInstance(m_strEncryptionAlgo);
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
			// Initialize cipher
			cipher.init(Cipher.DECRYPT_MODE, m_SecretKey, m_ivParameterSpec);
			return true;
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
	}
		
	private boolean validateSignature(byte[] dataBytes, byte[] signatureBytes)
	{
		try 
		{	
			// Get same signature algo
			Signature signature = Signature.getInstance(m_strSignatureAlgo);
			
			// Init for verification
			signature.initVerify(m_PublicKey);
			signature.update(dataBytes);
			
			// Verify
			return signature.verify(signatureBytes);		
		}		 
		catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
			return false;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return false;
		} catch (SignatureException e) {
			e.printStackTrace();
			return false;
		} 

	}
}
