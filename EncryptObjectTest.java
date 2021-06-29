import static org.junit.Assert.assertEquals;
	
	import java.io.ByteArrayInputStream;
	import java.io.ByteArrayOutputStream;
	import java.io.IOException;
	import java.io.ObjectInput;
	import java.io.ObjectInputStream;
	import java.io.ObjectOutput;
	import java.io.ObjectOutputStream;
	
	import org.junit.Test;
	
	public class EncryptObjectTest {
	
	    /**
	     * Test 'happy path'
	     */
	    @Test
	    public void testCipher() throws IOException, ClassNotFoundException {
	        EncryptObject secret1 = new EncryptObject("password");
	        EncryptObject secret2;
	        byte[] ser;
	
	        // serialize object
	        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
	                ObjectOutput output = new ObjectOutputStream(baos)) {
	            output.writeObject(secret1);
	            output.flush();
	
	            ser = baos.toByteArray();
	        }
	
	        // deserialize object.
	        try (ByteArrayInputStream bais = new ByteArrayInputStream(ser); ObjectInput input = new ObjectInputStream(bais)) {
	            secret2 = (EncryptObject) input.readObject();
	        }
	
	        // compare values.
	        assertEquals(secret1.getSecret(), secret2.getSecret());
	    }
	    
	
	    /**
	     * Test serialization after a single bit is flipped
	     */
	    @Test(expected = InvalidObjectException.class)
	    public void testCipherAltered() throws IOException, ClassNotFoundException {
	        EncryptObject secret1 = new EncryptObject("password");
	        EncryptObject secret2;
	        byte[] ser;
	
	        // serialize object
	        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
	                ObjectOutput output = new ObjectOutputStream(baos)) {
	            output.writeObject(secret1);
	            output.flush();
	
	            ser = baos.toByteArray();
	        }
	        
	        // corrupt ciphertext
	        ser[ser.length - 16 - 1 - 3] ^= 1;
	
	        // deserialize object.
	        try (ByteArrayInputStream bais = new ByteArrayInputStream(ser); ObjectInput input = new ObjectInputStream(bais)) {
	            secret2 = (EncryptObject) input.readObject();
	        }
	
	        // compare values.
	        assertEquals(secret1.getSecret(), secret2.getSecret());
	    }
	}

