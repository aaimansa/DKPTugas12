  import java.io.IOException;
	import java.io.InvalidObjectException;
	import java.io.ObjectInputStream;
	import java.io.ObjectOutputStream;
	import java.io.Serializable;
	import java.util.Arrays;
	
	import javax.crypto.Cipher;
	import javax.crypto.Mac;
	import javax.crypto.spec.IvParameterSpec;
	import javax.crypto.spec.SecretKeySpec;
	
	public class EncryptObject implements Serializable {
	    private static final long serialVersionUID = 1L;
	
	    private final String secret;
	
	    /**
	     * Constructor.
	     * 
	     * @param secret
	     */
	    public EncryptObject(final String secret) {
	        this.secret = secret;
	    }
	
	    /**
	     * Accessor
	     */
	    public String getSecret() {
	        return secret;
	    }
	
	    /**
	     * Replace the object being serialized with a proxy.
	     * 
	     * @return
	     */
	    private Object writeReplace() {
	        return new SimpleEncryptObjectProxy(this);
	    }
	
	    /**
	     * Serialize object. We throw an exception since this method should never be
	     * called - the standard serialization engine will serialize the proxy
	     * returned by writeReplace(). Anyone calling this method directly is
	     * probably up to no good.
	     * 
	     * @param stream
	     * @return
	     * @throws InvalidObjectException
	     */
	    private void writeObject(ObjectOutputStream stream) throws InvalidObjectException {
	        throw new InvalidObjectException("Proxy required");
	    }
	
	    /**
	     * Deserialize object. We throw an exception since this method should never
	     * be called - the standard serialization engine will create serialized
	     * proxies instead. Anyone calling this method directly is probably up to no
	     * good and using a manually constructed serialized object.
	     * 
	     * @param stream
	     * @return
	     * @throws InvalidObjectException
	     */
	    private void readObject(ObjectInputStream stream) throws InvalidObjectException {
	        throw new InvalidObjectException("Proxy required");
	    }
	
	    /**
	     * Serializable proxy for our protected class. The encryption code is based
	     * on https://gist.github.com/mping/3899247.
	     */
	    private static class SimpleEncryptObjectProxy implements Serializable {
	        private static final long serialVersionUID = 1L;
	        private String secret;
	
	        private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	        private static final String HMAC_ALGORITHM = "HmacSHA256";
	
	        private static transient SecretKeySpec cipherKey;
	        private static transient SecretKeySpec hmacKey;
	
	        static {
	            // these keys can be read from the environment, the filesystem, etc.
	            final byte[] aes_key = "d2cb415e067c7b13".getBytes();
	            final byte[] hmac_key = "d6cfaad283353507".getBytes();
	
	            try {
	                cipherKey = new SecretKeySpec(aes_key, "AES");
	                hmacKey = new SecretKeySpec(hmac_key, HMAC_ALGORITHM);
	            } catch (Exception e) {
	                throw new ExceptionInInitializerError(e);
	            }
	        }
	
	        /**
	         * Constructor.
	         * 
	         * @param EncryptObject
	         */
	        SimpleEncryptObjectProxy(EncryptObject EncryptObject) {
	            this.secret = EncryptObject.secret;
	        }
	
	        /**
	         * Write encrypted object to serialization stream.
	         * 
	         * @param s
	         * @throws IOException
	         */
	        private void writeObject(ObjectOutputStream s) throws IOException {
	            s.defaultWriteObject();
	            try {
	                Cipher encrypt = Cipher.getInstance(CIPHER_ALGORITHM);
	                encrypt.init(Cipher.ENCRYPT_MODE, cipherKey);
	                byte[] ciphertext = encrypt.doFinal(secret.getBytes("UTF-8"));
	                byte[] iv = encrypt.getIV();
	
	                Mac mac = Mac.getInstance(HMAC_ALGORITHM);
	                mac.init(hmacKey);
	                mac.update(iv);
	                byte[] hmac = mac.doFinal(ciphertext);
	
	                // TBD: write algorithm id...
	                s.writeInt(iv.length);
	                s.write(iv);
	                s.writeInt(ciphertext.length);
	                s.write(ciphertext);
	                s.writeInt(hmac.length);
	                s.write(hmac);
	            } catch (Exception e) {
	                throw new InvalidObjectException("unable to encrypt value");
	            }
	        }
	
	        /**
	         * Read encrypted object from serialization stream.
	         * 
	         * @param s
	         * @throws InvalidObjectException
	         */
	        private void readObject(ObjectInputStream s) throws ClassNotFoundException, IOException, InvalidObjectException {
	            s.defaultReadObject();
	            try {
	                // TBD: read algorithm id...
	                byte[] iv = new byte[s.readInt()];
	                s.read(iv);
	                byte[] ciphertext = new byte[s.readInt()];
	                s.read(ciphertext);
	                byte[] hmac = new byte[s.readInt()];
	                s.read(hmac);
	
	                // verify HMAC
	                Mac mac = Mac.getInstance(HMAC_ALGORITHM);
	                mac.init(hmacKey);
	                mac.update(iv);
	                byte[] signature = mac.doFinal(ciphertext);
	
	                // verify HMAC
	                if (!Arrays.equals(hmac, signature)) {
	                    throw new InvalidObjectException("unable to decrypt value");
	                }
	
	                // decrypt data
	                Cipher decrypt = Cipher.getInstance(CIPHER_ALGORITHM);
	                decrypt.init(Cipher.DECRYPT_MODE, cipherKey, new IvParameterSpec(iv));
	                byte[] data = decrypt.doFinal(ciphertext);
	                secret = new String(data, "UTF-8");
	            } catch (Exception e) {
	                throw new InvalidObjectException("unable to decrypt value");
	            }
	        }
	
	        /**
	         * Return protected object.
	         * 
	         * @return
	         */
	        private Object readResolve() {
	            return new EncryptObject(secret);
	        }
	    }
	}
