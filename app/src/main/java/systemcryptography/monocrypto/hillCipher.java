package systemcryptography.monocrypto;


import android.util.Log;

/**
 * Hill Cipher — polygraphic substitution using matrix multiplication (mod 26).
 *
 * This implementation uses a fixed 4×4 key matrix (no user-supplied key):
 *
 *   Encryption matrix K:
 *     [ 8   6   9   5 ]
 *     [ 6   9   5  10 ]
 *     [ 5   8   4   9 ]
 *     [10   6  11   4 ]
 *
 *   Decryption matrix K⁻¹ (mod 26):
 *     [23  20   5   1 ]
 *     [ 2  11  18   1 ]
 *     [ 2  20   6  25 ]
 *     [25   2  22  25 ]
 *
 * The cipher operates on a custom 26-character scrambled alphabet (arrayAlphabet)
 * rather than the standard a–z ordering. Only lowercase letters are supported;
 * the message is lowercased and stripped of non-alphabetic characters before
 * processing.
 *
 * Message blocks:
 *   - The message is split into 4-character blocks (the matrix dimension).
 *   - If the last block has fewer than 4 characters, it is padded with 'x'.
 *   - The first character of the split array is discarded (Java split artifact).
 *
 * Decryption removes trailing 'x' padding characters from the result.
 */
public class hillCipher {

    private final boolean needKey = false;

    // Custom scrambled alphabet used as the cipher's symbol set (26 chars)
    private final String [] arrayAlphabet = {
            "k", "p", "c", "o", "h", "a",
            "r", "n", "g", "z", "e", "y",
            "s", "m", "w", "f", "l", "v",
            "i", "q", "d", "u", "x", "b",
            "t", "j"
    };

    public hillCipher() {
    }

    public boolean getNeedKey() {
        return this.needKey;
    }

    /**
     * Returns the index of myChar in the scrambled alphabet, or -1 if not found.
     * The index is the numeric value used in matrix multiplication.
     */
    private int lookForChar(String myChar) {
        for(int i=0; i<this.arrayAlphabet.length; i++) {
            if( this.arrayAlphabet[i].compareTo(myChar) == 0 )
                return i;
        }

        return -1;
    }

    /**
     * Strips non-alphabetic characters and lowercases the message.
     * Only characters present in the scrambled alphabet survive.
     */
    private String cleanMessage( String message ) {
        String cleanMessage = "";
        for(int i=0; i<message.length(); i++) {
            if( lookForChar( message.substring( i,i+1 ).toLowerCase() ) >= 0 ) {
                cleanMessage = cleanMessage.concat( message.substring( i,i+1 ).toLowerCase() );
            }
        }

        return cleanMessage;
    }

    /**
     * Encrypts a message using the 4×4 Hill cipher key matrix.
     *
     * Steps:
     *   1. Clean and lowercase the message; discard the first split artifact.
     *   2. Split into 4-character blocks, padding the last block with 'x' if needed.
     *   3. For each block [p0,p1,p2,p3], compute:
     *        c0 = (8*p0 + 6*p1 + 9*p2 +  5*p3) % 26
     *        c1 = (6*p0 + 9*p1 + 5*p2 + 10*p3) % 26
     *        c2 = (5*p0 + 8*p1 + 4*p2 +  9*p3) % 26
     *        c3 = (10*p0+ 6*p1 +11*p2 +  4*p3) % 26
     *   4. Map output indices back to the scrambled alphabet.
     *
     * @param message Plaintext string
     * @return Ciphertext string
     */
    public String doCipher(String message) {

        String []  arrayCipherMessage;
        message = cleanMessage( message );
        String [] arrayMessage = message.split("");
        // Discard the empty first element produced by split("") on a non-empty string
        String [] myArray = new String [arrayMessage.length - 1];

        for(int g=1; g<arrayMessage.length; g++) {
            myArray[g-1] = arrayMessage[g];
        }

        arrayMessage = myArray;
        int rest = arrayMessage.length % 4;   // Remaining chars in the last partial block
        int blocks = arrayMessage.length / 4; // Number of complete 4-char blocks

        // Allocate output array; round up to the nearest multiple of 4
        if( rest > 0) {
            arrayCipherMessage = new String[ (blocks+1)*4 ];
        }
        else {
            arrayCipherMessage = new String[ blocks*4 ];
        }

        for(int i=0; i<arrayCipherMessage.length;) {

            if( (i+4) <= arrayMessage.length ) {
                // Full 4-character block: apply the encryption matrix directly
                Log.i("datos", arrayMessage[i]+":"+arrayMessage[i+1]+":"+arrayMessage[i+2]+":"+arrayMessage[i+3]+" rest: "+rest);
                arrayCipherMessage[i]   = this.arrayAlphabet[ ( (8 * lookForChar(arrayMessage[i])) + (6 * lookForChar(arrayMessage[i + 1])) + (9 * lookForChar(arrayMessage[i + 2])) + (5 * lookForChar(arrayMessage[i + 3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+1] = this.arrayAlphabet[ ( (6 * lookForChar(arrayMessage[i])) + (9 * lookForChar(arrayMessage[i + 1])) + (5 * lookForChar(arrayMessage[i + 2])) + (10 * lookForChar(arrayMessage[i + 3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+2] = this.arrayAlphabet[ ( (5 * lookForChar(arrayMessage[i])) + (8 * lookForChar(arrayMessage[i + 1])) + (4 * lookForChar(arrayMessage[i + 2])) + (9 * lookForChar(arrayMessage[i + 3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+3] = this.arrayAlphabet[ ( (10 * lookForChar(arrayMessage[i])) + (6 * lookForChar(arrayMessage[i + 1])) + (11 * lookForChar(arrayMessage[i + 2])) + (4 * lookForChar(arrayMessage[i + 3])) ) % this.arrayAlphabet.length];
            }
            else {
                // Partial last block: pad missing positions with 'x' before multiplying
                String lastBlock [] = new String [4];
                for(int j=0; j<4; j++) {
                    if( j < rest  && (i+j) <arrayMessage.length) {
                        lastBlock[j] = arrayMessage[i+j];
                    }
                    else {
                        lastBlock[j] = "x";  // Padding character
                    }
                }

                Log.i("datos", lastBlock[0]+":"+lastBlock[1]+":"+lastBlock[2]+":"+lastBlock[3]);
                arrayCipherMessage[i]   = this.arrayAlphabet[ ( (8 * lookForChar(lastBlock[0])) + (6 * lookForChar(lastBlock[1])) + (9 * lookForChar(lastBlock[2])) + (5 * lookForChar(lastBlock[3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+1] = this.arrayAlphabet[ ( (6 * lookForChar(lastBlock[0])) + (9 * lookForChar(lastBlock[1])) + (5 * lookForChar(lastBlock[2])) + (10 * lookForChar(lastBlock[3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+2] = this.arrayAlphabet[ ( (5 * lookForChar(lastBlock[0])) + (8 * lookForChar(lastBlock[1])) + (4 * lookForChar(lastBlock[2])) + (9 * lookForChar(lastBlock[3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+3] = this.arrayAlphabet[ ( (10 * lookForChar(lastBlock[0])) + (6 * lookForChar(lastBlock[1])) + (11 * lookForChar(lastBlock[2])) + (4 * lookForChar(lastBlock[3])) ) % this.arrayAlphabet.length];

            }

            i += 4;
        }

        String cipherMessage = "";
        for (int j=0; j<arrayCipherMessage.length; j++) {
            cipherMessage = cipherMessage.concat(arrayCipherMessage[j]);
        }

        return new String(cipherMessage);
    }

    /**
     * Decrypts a Hill-cipher message using the precomputed inverse matrix K⁻¹ (mod 26).
     *
     * Steps:
     *   1. Split into 4-character blocks (same split-artifact handling as doCipher).
     *   2. For each block [c0,c1,c2,c3], compute:
     *        p0 = (23*c0 + 20*c1 +  5*c2 +  1*c3) % 26
     *        p1 = ( 2*c0 + 11*c1 + 18*c2 +  1*c3) % 26
     *        p2 = ( 2*c0 + 20*c1 +  6*c2 + 25*c3) % 26
     *        p3 = (25*c0 +  2*c1 + 22*c2 + 25*c3) % 26
     *   3. Strip trailing 'x' padding from the final result.
     *
     * @param message Ciphertext string
     * @return Decrypted plaintext string
     */
    public String doDecoding(String message) {

        String []  arrayCipherMessage;
        String [] arrayMessage = message.split("");
        // Discard the empty first element produced by split("")
        String [] myArray = new String [arrayMessage.length - 1];

        for(int g=1; g<arrayMessage.length; g++) {
            myArray[g-1] = arrayMessage[g];
        }

        arrayMessage = myArray;
        int rest = arrayMessage.length % 4;
        int blocks = arrayMessage.length / 4;

        if( rest > 0) {
            arrayCipherMessage = new String[ (blocks+1)*4 ];
        }
        else {
            arrayCipherMessage = new String[ blocks*4 ];
        }

        for(int i=0; i<arrayCipherMessage.length;) {

            if( (i+4) <= arrayMessage.length ) {
                // Full block: apply the inverse matrix
                arrayCipherMessage[i]   = this.arrayAlphabet[ ( (23 * lookForChar(arrayMessage[i])) + (20 * lookForChar(arrayMessage[i + 1])) + (5 * lookForChar(arrayMessage[i + 2])) + ( 1 * lookForChar(arrayMessage[i + 3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+1] = this.arrayAlphabet[ ( (2 * lookForChar(arrayMessage[i])) + (11 * lookForChar(arrayMessage[i + 1])) + (18 * lookForChar(arrayMessage[i + 2])) + ( 1 * lookForChar(arrayMessage[i + 3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+2] = this.arrayAlphabet[ ( (2 * lookForChar(arrayMessage[i])) + (20 * lookForChar(arrayMessage[i + 1])) + (6 * lookForChar(arrayMessage[i + 2])) + (25 * lookForChar(arrayMessage[i + 3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+3] = this.arrayAlphabet[ ( (25 * lookForChar(arrayMessage[i])) + (2 * lookForChar(arrayMessage[i + 1])) + (22 * lookForChar(arrayMessage[i + 2])) + (25 * lookForChar(arrayMessage[i + 3])) ) % this.arrayAlphabet.length];
            }
            else {
                // Partial block: pad with 'x' before applying inverse matrix
                String lastBlock [] = new String [4];
                for(int j=0; j<4; j++) {
                    if( j < rest ) {
                        lastBlock[j] = arrayMessage[i+j];
                    }
                    else {
                        lastBlock[j] = "x";
                    }
                }
                arrayCipherMessage[i]   = this.arrayAlphabet[ ( (23 * lookForChar(lastBlock[0])) + (20 * lookForChar(lastBlock[1])) + (5 * lookForChar(lastBlock[2])) + (1 * lookForChar(lastBlock[3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+1] = this.arrayAlphabet[ ( (2 * lookForChar(lastBlock[0])) + (11 * lookForChar(lastBlock[1])) + (18 * lookForChar(lastBlock[2])) + (1 * lookForChar(lastBlock[3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+2] = this.arrayAlphabet[ ( (2 * lookForChar(lastBlock[0])) + (20 * lookForChar(lastBlock[1])) + (6 * lookForChar(lastBlock[2])) + (25 * lookForChar(lastBlock[3])) ) % this.arrayAlphabet.length];
                arrayCipherMessage[i+3] = this.arrayAlphabet[ ( (25 * lookForChar(lastBlock[0])) + (2 * lookForChar(lastBlock[1])) + (22 * lookForChar(lastBlock[2])) + (25 * lookForChar(lastBlock[3])) ) % this.arrayAlphabet.length];

            }

            i += 4;
        }

        String cipherMessage = "";
        for (int j=0; j<arrayCipherMessage.length; j++) {
            cipherMessage = cipherMessage.concat(arrayCipherMessage[j]);
        }

        // Remove trailing 'x' padding characters added during encryption
        for(int t=cipherMessage.length(); t>0; t--) {
            if( cipherMessage.substring(t-1, t).compareTo("x") != 0 ) {
                cipherMessage = cipherMessage.substring(0, t);
                break;
            }
        }

        return cipherMessage;
    }
}
