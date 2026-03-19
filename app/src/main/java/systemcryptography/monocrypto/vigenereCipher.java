package systemcryptography.monocrypto;

/**
 * Vigenère Cipher — polyalphabetic substitution cipher.
 *
 * Works over an extended 95-character alphabet (ASCII 32–126), not just the
 * traditional 26-letter alphabet. This allows encrypting spaces, digits,
 * punctuation, and mixed-case text.
 *
 * Encryption: C[i] = (P[i] + K[i % keyLen]) % alphabetSize
 * Decryption: P[i] = (C[i] - K[i % keyLen] + alphabetSize) % alphabetSize
 *
 * Where indices are positions in arrayAlphabetExt (0-based).
 *
 * Characters not present in arrayAlphabetExt are silently dropped during
 * cleanMessage() — they do not appear in the output.
 */
public class vigenereCipher {

    private String password;
    private final boolean needKey = true;

    // Standard 26-letter lowercase alphabet (used internally for key validation)
    private final String [] arrayAlphabet = {
            "a", "b", "c", "d", "e", "f",
            "g", "h", "i", "j", "k","l",
            "m", "n", "o", "p","q",
            "r", "s", "t", "u","v","w",
            "x", "y", "z"
    };

    // Extended 95-character working alphabet: space through '~' (ASCII 32–126)
    // This is the full set of printable ASCII characters used for encryption
    private final String [] arrayAlphabetExt = {
            " ", "!", "\"", "#", "$","%","&","'","!", ")",
            "*", "+", ",", "-", ".", "/", "0", "1", "2", "3",
            "4", "5", "6", "7", "8", "9", ":", ";", "<", "=",
            ">", "?", "@", "A", "B", "C", "D", "E", "F", "G",
            "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q",
            "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "[",
            "\\", "]", "^", "_", "`", "a", "b", "c", "d", "e",
            "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
            "p", "q", "r", "s", "t", "u", "v", "w", "x", "y",
            "z", "{", "|", "}", "~"
    };

    /**
     * Sets the cipher key. The password is cleaned to remove characters
     * not present in the working alphabet before storing.
     */
    public  void setPassword( String password ) {
        this.password = cleanMessage( password );
    }

    public boolean getNeedKey() {
        return this.needKey;
    }

    /**
     * Returns the index of myChar in arrayAlphabetExt, or -1 if not found.
     * Used to map a character to its numeric position for modular arithmetic.
     */
    private int lookForChar(String myChar) {
        for(int i=0; i<this.arrayAlphabetExt.length; i++) {
            if( this.arrayAlphabetExt[i].compareTo(myChar) == 0 )
                return i;
        }

        return -1;
    }

    /**
     * Strips characters not in the working alphabet from a string.
     * Applied to both the password and the message before processing.
     */
    private String cleanMessage( String message ) {
        String cleanMessage = "";
        for( int i=0; i<message.length(); i++ ) {
            if( lookForChar( message.substring( i,i+1 ) ) >= 0 ) {
                cleanMessage = cleanMessage.concat( message.substring( i,i+1 ) );
            }
        }
        return cleanMessage;
    }


    /**
     * Encrypts a plaintext string using the Vigenère cipher.
     *
     * The key repeats cyclically over the message. For each character:
     *   encryptedIndex = (messageIndex + keyIndex) % alphabetSize
     *
     * Characters outside the working alphabet are silently dropped.
     *
     * @param message Plaintext to encrypt
     * @return Ciphertext string
     */
    public String doCipher(String message) {

        message = cleanMessage( message );
        String [] arrayMessage = message.split("");
        String  cipherMessage = "";
        int indexPassword = 0;  // Cycles through the key characters

        for(int i=0; i<arrayMessage.length; i++) {

            if( lookForChar(arrayMessage[i]) != -1 ) {

                // Wrap key index back to 0 when it reaches the end of the key
                if( indexPassword >= this.password.length() ) indexPassword = 0;
                cipherMessage = cipherMessage.concat( this.arrayAlphabetExt[ ( lookForChar(this.password.substring(indexPassword, indexPassword+1)) + lookForChar(arrayMessage[i]) ) % this.arrayAlphabetExt.length ] );

                indexPassword++;
            }
        }

        return cipherMessage;
    }

    /**
     * Decrypts a Vigenère-encrypted string.
     *
     * For each character:
     *   decryptedIndex = (cipherIndex - keyIndex + alphabetSize) % alphabetSize
     *
     * The addition of alphabetSize prevents negative modulo results.
     *
     * @param message Ciphertext to decrypt
     * @return Decrypted plaintext string
     */
    public String doDecoding(String message) {
        String [] arrayMessage = message.split("");
        String  cipherMessage = "";
        int indexPassword = 0;
        int result;

        for(int i=0; i<arrayMessage.length; i++) {

            if( lookForChar(arrayMessage[i]) != -1 ) {

                if( indexPassword >= this.password.length() ) indexPassword = 0;

                result = lookForChar(arrayMessage[i]) - lookForChar( this.password.substring(indexPassword, indexPassword+1) ) ;

                // Guard against negative modulo (Java % can return negative values)
                if(result < 0) result = result + this.arrayAlphabetExt.length;

                cipherMessage = cipherMessage.concat( this.arrayAlphabetExt[ result % this.arrayAlphabetExt.length ] );
                indexPassword++;
            }
        }

        return cipherMessage;
    }
}
