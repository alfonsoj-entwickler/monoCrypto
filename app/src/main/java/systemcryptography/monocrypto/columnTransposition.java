package systemcryptography.monocrypto;


import android.util.Log;

/**
 * Columnar Transposition Cipher.
 *
 * The message is written into a grid row-by-row, then read off column-by-column
 * in an order determined by the alphabetical ranking of the key letters.
 *
 * Example with key "zebra" (alphabetical order: a=4, b=2, e=1, r=3, z=0 → column order 4,2,1,3,0):
 *
 *   Message: "WEAREDISCOVEREDFLEEAATONCE"
 *
 *   Grid (5 cols = key length):
 *     z  e  b  r  a
 *     W  E  A  R  E
 *     D  I  S  C  O
 *     ...
 *
 *   Ciphertext: read columns in alphabetical key order.
 *
 * Padding:
 *   - Cells beyond the message length are filled with 'x'.
 *   - Trailing 'x' padding is stripped during decryption.
 *
 * Key handling:
 *   - The key is deduplicated and lowercased (cleanPassword).
 *   - passwordColumn = key length = number of grid columns.
 *   - Column reading order is derived by sorting key letters alphabetically
 *     (ASCII code scan from 'a'=97 to 'y'=121) and recording their original positions.
 */
public class columnTransposition {

    private int passwordColumn;  // Number of columns in the transposition grid
    private String password;     // Cleaned, deduplicated key word
    private final boolean needKey = true;

    // Working alphabet: only lowercase a–z characters are processed
    private final String [] arrayAlphabet = {
            "a", "b", "c", "d", "e", "f",
            "g", "h", "i", "j", "k", "l",
            "m", "n", "o", "p", "q",
            "r", "s", "t", "u", "v", "w",
            "x", "y", "z"
    };

    /** Sets the key as a numeric column count (used when no keyword is available). */
    public  void setPassword( int password ) {
        this.passwordColumn = password;
    }

    /** Sets the key from a string keyword; derives column count from the cleaned key length. */
    public  void setPassword( String password ) {
        this.password = cleanPassword( password );
        this.passwordColumn = this.password.length();
    }

    public boolean getNeedKey() {
        return this.needKey;
    }

    /**
     * Cleans the key: lowercase, remove spaces and duplicate characters, and
     * keep only letters present in the working alphabet.
     *
     * @param password Raw keyword
     * @return Cleaned deduplicated key
     */
    private String cleanPassword( String password ) {

        String myPassword = password;
        String cleanPassword = "";


        for(int i = 0; i < myPassword.length(); i++) {

            if ( cleanPassword.length() == 0 ) {
                cleanPassword = cleanPassword.concat( myPassword.substring(i,i+1).toLowerCase() );
                //System.out.println("Codigo password: " + myPassword.substring(i,i+1).codePointAt(0) );
            }

            if ( myPassword.substring(i,i+1).compareTo(" ") == 0 )continue;

            else {
                boolean jumpChar = false;

                for(int j=0; j < cleanPassword.length(); j++) {

                    if( cleanPassword.substring(j,j+1).compareTo( myPassword.substring(i,i+1).toLowerCase() ) == 0 ) {
                        jumpChar = true;
                        break;
                    }
                }

                if(!jumpChar) {
                    cleanPassword = cleanPassword.concat( myPassword.substring(i,i+1).toLowerCase() );
                    //System.out.println("Codigo password: " + myPassword.substring(i,i+1).codePointAt(0) );
                }
            }
        }

        cleanPassword = cleanMessage( cleanPassword );
        return cleanPassword;
    }

    /**
     * Returns the index of a letter in the working alphabet, or -1 if not found.
     * Used to validate and strip non-alphabetic characters from the message.
     */
    private int lookForLetter( String letter ) {

        for(int i=0; i<this.arrayAlphabet.length;i++) {


                if( this.arrayAlphabet[i].compareTo(letter) == 0 ) {
                    int  position = i;
                    return position;
                }

        }

        return -1;
    }

    /** Removes non-alphabetic characters and lowercases the message. */
    public String cleanMessage( String message ) {

        String cleanMessage = "";

        for(int i=0; i<message.length(); i++) {
            if ( lookForLetter( message.substring(i,i+1).toLowerCase() ) != -1 ) {
                cleanMessage = cleanMessage.concat( message.substring(i,i+1).toLowerCase() );
            }
        }

        return cleanMessage;
    }

    /**
     * Encrypts a message using columnar transposition.
     *
     * Steps:
     *   1. Fill a rows×passwordColumn grid with message characters (row by row).
     *      Empty cells at the end are padded with 'x'.
     *   2. Compute column reading order by sorting key letters alphabetically:
     *      scan ASCII codes 97–121 ('a'–'y') and record the original column index
     *      of each matching key letter → orderColumn[].
     *   3. Read the grid column by column in orderColumn sequence to produce ciphertext.
     *
     * Note: split("") on a non-empty string produces an empty first element in
     * Java/Android; the grid fill loop starts at index 1 to skip it (number=1).
     *
     * @param message Plaintext string
     * @return Ciphertext string
     */
    public String doCipher(String message) {
        String [] arrayMessage = message.split("");
        String cipherMessage = "";

        // Calculate number of rows needed to hold the message
        int rows = (int)Math.ceil( new Double(arrayMessage.length - 1) / new Double(this.passwordColumn) );

        String [][] arrayCipher = new String [rows][this.passwordColumn];

        // Fill the grid row-by-row; pad remaining cells with 'x'
        int number = 1;  // Start at 1 to skip the empty split artifact
        for(int i=0; i<arrayCipher.length; i++) {

            for(int j=0; j<arrayCipher[0].length; j++) {
                if( number >= arrayMessage.length ) {
                    arrayCipher [i][j] = "x";
                    Log.i("entrada1","("+i+","+j+"): x");
                }
                else {
                    arrayCipher [i][j] = arrayMessage[number];
                    Log.i("entrada1","("+i+","+j+"): "+arrayCipher [i][j]);
                    number++;
                }
            }
        }

        // Build column reading order by alphabetical ranking of key letters
        // Scan ASCII 'a'(97) to 'y'(121) and record the key position of each match
        int [] orderColumn = new int[ this.password.length() ];

        //System.out.println();

        int indexOrders = 0;

        for( int j=97; j<122; j++ ) {

            for(int h=0; h<this.password.length(); h++) {

                if( j == this.password.substring(h,h+1).codePointAt(0) ) {
                    orderColumn[indexOrders] = h;  // h = original column index of this letter
                    //System.out.print("("+indexOrders+"):"+h+" ");
                    indexOrders++;
                    continue;
                }
            }
        }

        // Read columns in alphabetical order to produce ciphertext
//        number = 0;
        for(int c=0; c<orderColumn.length; c++) {
            for(int r=0; r<arrayCipher.length; r++) {
                //if( number >= arrayMessage.length ||  arrayCipher[r][c] == null) continue;
                cipherMessage = cipherMessage.concat(arrayCipher[r][orderColumn[c]]);
 //               number++;
            }
        }
        return cipherMessage;
    }

    /**
     * Decrypts a columnar-transposition ciphertext.
     *
     * Steps:
     *   1. Fill the grid COLUMN-by-column (reading the ciphertext in column order).
     *   2. Compute the same alphabetical column ordering used during encryption.
     *   3. Invert the orderColumn mapping so we know which original column each
     *      position in the sorted order maps back to (newOrderColumn[]).
     *   4. Read the grid ROW-by-row with the inverted column order to recover the
     *      original message.
     *   5. Strip trailing 'x' padding characters.
     *
     * @param message Ciphertext string
     * @return Decrypted plaintext string
     */
    public String doDecoding(String message) {
        String [] arrayMessage = message.split("");
        String cipherMessage = "";

        int rows = (int)Math.ceil( new Double(arrayMessage.length - 1) / new Double(this.passwordColumn) );

        String [][] arrayCipher = new String [rows][this.passwordColumn];

        // Fill the grid column-by-column (inverse of encryption's row-by-row fill)
        int number = 1;
        for(int i=0; i<arrayCipher[0].length; i++) {
            for(int j=0; j<arrayCipher.length; j++) {
                if( number >= arrayMessage.length ) {
                    arrayCipher [j][i] = "x";
                    Log.i("salida1","("+j+","+i+"): Null");
                    continue;
                }
                else {
                    arrayCipher [j][i] = arrayMessage[number];
                    Log.i("salida1","("+j+","+i+"):"+arrayCipher [j][i]);
                    number++;
                }
            }
        }

        // Re-derive the same column ordering used during encryption
        int [] orderColumn = new int[ this.password.length() ];

        //System.out.println();

        int indexOrders = 0;

        for( int j=97; j<122; j++ ) {

            for(int h=0; h<this.password.length(); h++) {

                if( j == this.password.substring(h,h+1).codePointAt(0) ) {
                    orderColumn[indexOrders] = h;
                    //System.out.print("("+indexOrders+"):"+h+" ");
                    indexOrders++;
                    continue;
                }
            }
        }

        //System.out.println();

        // Invert orderColumn: newOrderColumn[originalPos] = sortedPos
        // This maps from the original grid column index back to its reading position
        int [] newOrderColumn = new int [orderColumn.length];
        for(int i=0; i<newOrderColumn.length; i++) {
            for(int j=0; j<orderColumn.length; j++) {
                if( orderColumn[j] == i ){
                    newOrderColumn[i] = j;
                    //System.out.print("("+i+"):"+j+" ");
                }
            }
        }

        orderColumn = newOrderColumn;

        //System.out.println();

        // Read grid row-by-row using the inverted column order
        //number = 0;
        for(int c=0; c<arrayCipher.length; c++) {
            for(int r=0; r<arrayCipher[0].length; r++) {
                //if( number >= arrayMessage.length ||  arrayCipher[c][r] == null) continue;
                cipherMessage = cipherMessage.concat(arrayCipher[c][orderColumn[r]]);
                Log.i("salida2","("+c+","+r+"):"+arrayCipher[c][orderColumn[r]]);
                //number++;
            }
        }

        // Strip trailing 'x' padding from the recovered plaintext
        for(int g=cipherMessage.length(); g>0; g--) {
            if( cipherMessage.substring(g-1, g).compareTo("x") != 0 ) {
                cipherMessage = cipherMessage.substring(0, g);
                break;
            }
        }

        return cipherMessage;
    }
}
