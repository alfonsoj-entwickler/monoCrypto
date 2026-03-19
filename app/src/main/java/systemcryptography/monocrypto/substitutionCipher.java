package systemcryptography.monocrypto;

/**
 * Substitution Cipher — affine cipher over a printable-ASCII alphabet.
 *
 * The cipher operates on the range ASCII 32 (' ') to ASCII 126 ('~'), giving
 * an alphabet of 95 characters.
 *
 * When a password is provided the alphabet is rearranged so that the key
 * characters appear first (deduplicated, with a positional offset po), making
 * this a keyed affine substitution.
 *
 * Encryption formula (index space):
 *   cipherPos = (b + plainPos * a) % alphabetLength
 *
 * Decryption formula (index space):
 *   plainPos  = (a * (cipherPos + alphabetLength - b)) % alphabetLength
 *
 * Characters outside the printable ASCII range are passed through unchanged.
 */
public class substitutionCipher {

    // Inclusive bounds of the printable ASCII range used as the working alphabet
    private final byte limitS = 126;  // '~'
    private final byte limitI = 32;   // ' '

    // Affine parameters: multiplier (a), shift (b), and key offset (po)
    private byte a, b, po;
    private String password;

    // The working alphabet byte array — rearranged when a password is supplied
    private byte[] alphabet;
    private final boolean needKey = true;

    /**
     * Simple constructor without a password — plain affine cipher.
     */
    public substitutionCipher (byte a, byte b) {
        this.a = a;
        this.b = b;
        this.po = 0;
        this.password = "";
        this.alphabet = new byte[ (limitS - limitI) + 1 ];
        getAlphabetAscii();
    }

    /**
     * Full constructor — keyed affine cipher.
     * The password is deduplicated and used to reorder the alphabet.
     */
    public substitutionCipher (byte a, byte b, byte po, String password ) {
        this.a = a;
        this.b = b;
        this.po = po;
        this.password = cleanRepeatWords(password);
        this.alphabet = new byte[ (limitS - limitI) + 1 ];
        getAlphabetAscii();
        // Build password-keyed alphabet: key chars first, then remaining chars, shifted by po
        this.alphabet = getAlphabetwithPassword( this.password, new String( this.alphabet ) ).getBytes();

    }

    public boolean getNeedKey() {
        return this.needKey;
    }

    public byte getA() {
        return this.a;
    }

    public byte getB() {
        return this.b;
    }

    public byte getPO() {
        return this.po;
    }

    public String getPassword() {
        return this.password;
    }

    public byte [] getAlphabet() {
        return this.alphabet;
    }

    public void setA(byte a) {
        this.a = a;
    }

    public void setB(byte b) {
        this.b = b;
    }

    public void setPO(byte po) {
        this.po = po;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Encrypts a byte array message.
     * Characters not found in the alphabet (outside printable ASCII) are kept as-is.
     *
     * @param message Raw bytes to encrypt
     * @return Encrypted string
     */
    public String doCipher(byte[] message) {
        byte[]  cipherMessage = new byte[message.length];

        for(int i=0; i<message.length; i++) {

            if( lookForChar(message[i]) == -1 ) {
                // Character is outside the working alphabet — pass through unchanged
                cipherMessage[i] = message[i];
            }
            else {
                //cipherMessage[i] = (byte) ((this.b + (message[i] * this.a)) % limitS);
                // Apply affine mapping: cipherPos = (b + plainPos * a) % len
                cipherMessage[i] = this.alphabet[(int)( ( this.b + ( lookForChar( message[i] ) * this.a ) ) % this.alphabet.length )];
            }
        }

        return new String(cipherMessage);
    }

    /**
     * Decrypts a byte array message using the inverse affine mapping.
     * Characters not in the alphabet are kept as-is.
     *
     * @param message Raw bytes to decrypt
     * @return Decrypted string
     */
    public String doDecoding(byte[] message){
        byte[] plainTextMessage = new byte[message.length];

        for(int i=0; i<message.length;i++) {
            if( lookForChar(message[i]) != -1)
                // Inverse: plainPos = a * (cipherPos + len - b) % len
                plainTextMessage[i] = this.alphabet[(int)( ( this.a * ( lookForChar( message[i] ) + this.alphabet.length - this.b) ) % this.alphabet.length )];
            else
                plainTextMessage[i] = message[i];
        }

        return new String(plainTextMessage);

    }

    /**
     * Populates the alphabet array with the printable ASCII characters (32–126).
     */
    public void getAlphabetAscii() {
        for(int i=0; i<this.alphabet.length; i++) {
            this.alphabet[i] = (byte)(limitI + i);
        }
    }

    /**
     * Returns the index of byte n in the working alphabet, or -1 if not found.
     * Used to map a character to its positional index before the affine transform.
     */
    public int lookForChar(byte n) {
        for(int i = 0; i < this.alphabet.length; i++) {
            if(this.alphabet[i] == n) return i;
        }
        return -1;
    }

    /**
     * Builds a password-keyed alphabet.
     *
     * Construction:
     *   block1 = ASCII alphabet characters NOT present in the password (preserving order)
     *   block2 = password + block1[0 .. len-po-1]
     *   result = block1[len-po .. len-1] + block2
     *
     * The po offset rotates the non-key portion, adding another degree of freedom.
     *
     * @param yourPassword   Deduplicated key string
     * @param alphabetASCII  The base ASCII alphabet as a string
     * @return The reordered alphabet string
     */
    public String getAlphabetwithPassword(String yourPassword, String alphabetASCII) {

        String [] arrayMyAlphabet = alphabetASCII.split("");
        String [] arrayPassword = yourPassword.split("");

        String block1 = "";
        String block2 = "";
        String myNewAlphabetwithPassword;

        // Collect all characters that are NOT in the password
        for(int i=0; i<arrayMyAlphabet.length; i++) {
            boolean jumpChar = false;

            for(int j=0; j<arrayPassword.length; j++) {
                if( arrayMyAlphabet[i].compareTo(arrayPassword[j]) == 0 ) jumpChar = true;
            }

            if(!jumpChar) block1 = block1.concat( arrayMyAlphabet[i] );
        }

        block2 = yourPassword.concat(block1.substring(0, block1.length() - (int) this.po));
        myNewAlphabetwithPassword = block1.substring( block1.length() - (int)this.po, block1.length()  ).concat(block2);

        return myNewAlphabetwithPassword;
    }

    /**
     * Removes duplicate characters from the password, preserving first-occurrence order.
     * This ensures the alphabet reordering step has a unique, well-defined key.
     *
     * @param keyWord The raw password string
     * @return Deduplicated password
     */
    public String cleanRepeatWords(String keyWord){
        String[] arrayPassword = keyWord.split("");
        String cleanPassword = "";


        for(int i = 0; i < arrayPassword.length; i++) {

            if ( cleanPassword.length() == 0 )cleanPassword = cleanPassword.concat(arrayPassword[i]);
            else {
                boolean jumpChar = false;
                String [] arrayCleanPassword = cleanPassword.split("");

                for(int j=0; j<arrayCleanPassword.length; j++) {
                    if(arrayCleanPassword[j].compareTo(arrayPassword[i]) == 0){
                        jumpChar = true;
                        break;
                    }
                }

                if(!jumpChar) cleanPassword = cleanPassword.concat(arrayPassword[i]);
            }
        }

        return cleanPassword;
    }
}
