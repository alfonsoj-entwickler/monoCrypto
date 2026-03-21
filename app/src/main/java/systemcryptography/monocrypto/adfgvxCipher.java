package systemcryptography.monocrypto;


/**
 * ADFGVX Cipher — fractionating transposition cipher used in WWI by the German Army.
 *
 * The cipher combines two operations:
 *   1. Polybius-style fractionation: each character is replaced by a pair of
 *      letters from the set {A, D, F, G, V, X} using a 6×6 substitution grid.
 *   2. Columnar transposition: the resulting pair sequence is rearranged using
 *      the key word to reorder columns.
 *
 * The 6×6 grid (arrayAdfgx) maps 36 symbols (a–z + 0–9) to coordinate pairs.
 * Coordinates are expressed using the index letters {a, d, f, g, v, x} (indexArray).
 *
 * Encryption overview:
 *   plaintext → fractionated pairs → write into grid → read columns in key order
 *
 * Decryption overview:
 *   ciphertext → reconstruct grid (fill column by column in key order)
 *   → read grid row by row → convert each pair back to plaintext character
 *
 * Padding:
 *   During encryption, grid cells beyond the pair sequence length are padded with 'z'.
 *   During decryption, any pair where either coordinate is 'z' signals end-of-message.
 *
 * Key handling (same algorithm as columnTransposition):
 *   - Deduplicated and lowercased.
 *   - Column reading order determined by alphabetical rank of key letters.
 */
public class adfgvxCipher {

    // The six fractionation symbols used as row/column coordinates
    private final String [] indexArray = { "a", "d", "f", "g", "v", "x" };

    // 6×6 substitution grid: maps plaintext characters to (row, col) positions
    // Row index → indexArray[row], Column index → indexArray[col]
    private final String [][] arrayAdfgx = {
            {"n", "a", "1", "c", "3", "h"},
            {"8", "t", "b", "2", "o", "m"},
            {"e", "5", "w", "r", "p", "d"},
            {"4", "f", "6", "g", "7", "i"},
            {"9", "j", "0", "k", "l", "q"},
            {"s", "u", "v", "x", "y", "z"},
    };


    private String password;

    /**
     * Constructs an ADFGVX cipher with the given key.
     * The key is immediately cleaned and deduplicated.
     */
    public adfgvxCipher( String password ) {
        this.password = cleanPassword( password );
        //System.out.println("Generada clase adfgxCipher.");
    }

    /**
     * Encrypts a message using the ADFGVX cipher.
     *
     * Steps:
     *   1. Clean the message (keep only characters present in arrayAdfgx).
     *   2. Substitute each character with its two-letter coordinate pair from indexArray.
     *   3. Write the resulting string into a rows×keyLength grid (row by row).
     *      Pad empty trailing cells with 'z'.
     *   4. Determine column reading order from alphabetical key ranking.
     *   5. Read columns in that order to produce the final ciphertext.
     *
     * @param message Plaintext string
     * @return ADFGVX ciphertext string
     */
    public String doCipher( String message ) {

        String cipherMessage = "";
        message = cleanMessage( message );

        ////System.out.println("Mensaje limpio de verdad: " + message);
        ////System.out.println("Password limpio de verdad: " + this.password);

        // Step 1–2: substitute each plaintext character with its ADFGVX coordinate pair
        for(int i=0; i<message.length(); i++) {
            int [] positions = lookForLetter( message.substring(i,i+1) );

            if(positions != null) {
                // positions[0] = row index, positions[1] = column index in arrayAdfgx
                cipherMessage = cipherMessage.concat( this.indexArray[ positions[0] ].concat( this.indexArray[ positions[1] ] ) );
            }

        }

        // Step 3: lay out the fractionated pairs into a grid (rows × keyLength)
        int row = (int)Math.ceil( (double)cipherMessage.length()/(double)this.password.length() );
        int column = this.password.length();

        //System.out.println("Array creado n= "+ row +", m= " + column );

        String [][] arrayMessage = new String[ row ][ column ];
        int iC = 0;

        for(int i=0; i<arrayMessage.length; i++) {
            //System.out.println();
            for(int j=0; j<arrayMessage[0].length; j++) {

                if( iC < cipherMessage.length() ) {
                    arrayMessage[i][j] = cipherMessage.substring( iC, iC+1 );
                    //System.out.print("("+i+","+j+"):"+arrayMessage[i][j]+" ");
                    iC++;
                }
                else {
                    // Pad empty trailing cells with 'z' (signals end in decryption)
                    arrayMessage[i][j] = "z";
                    //System.out.print("("+i+","+j+"):"+arrayMessage[i][j]+" ");
                }
            }
        }

        // Step 4: compute column reading order from alphabetical key ranking
        int [] orderColumn = new int[ this.password.length() ];

        //System.out.println();

        int indexOrders = 0;

        for( int j=97; j<122; j++ ) {

            for(int h=0; h<this.password.length(); h++) {

                if( j == this.password.substring(h,h+1).codePointAt(0) ) {
                    orderColumn[indexOrders] = h;
                    //System.out.print("("+indexOrders+"):"+h+" ");
                    indexOrders++;
                }
            }
        }

        //System.out.println();

        // Step 5: read grid columns in alphabetical key order
        cipherMessage = "";
        for(int j=0; j<arrayMessage[0].length; j++) {
            for(int i=0; i<arrayMessage.length; i++) {
                cipherMessage = cipherMessage.concat( arrayMessage[i][ orderColumn[j] ] );
                //System.out.print( arrayMessage[i][ orderColumn[j] ] );
            }
            //System.out.println();
        }

        //System.out.println();

        return cipherMessage;
    }

    /**
     * Decrypts an ADFGVX ciphertext.
     *
     * Steps:
     *   1. Reconstruct the transposition grid by filling it column-by-column
     *      in alphabetical key order (reverses the column-reading step).
     *   2. Invert the column order mapping to recover the original row-by-row layout.
     *   3. Read the grid row-by-row to get the fractionated pair sequence.
     *   4. Convert each coordinate pair back to a plaintext character via arrayAdfgx.
     *      Stop when a 'z' padding symbol is encountered.
     *
     * @param message ADFGVX ciphertext
     * @return Decrypted plaintext string
     */
    public String doDecoding( String message ) {

        String cipherMessage = "";

        //System.out.println("Mensaje limpio de verdad: " + message);
        //System.out.println("Password limpio de verdad: " + this.password);

        // Step 1: reconstruct the grid — fill column by column in key order
        int row = (int)Math.ceil( (double)message.length()/(double)this.password.length() );
        int column = this.password.length();

        //System.out.println("Array creado n= "+ row +", m= " + column );

        String [][] arrayMessage = new String[ row ][ column ];
        int iC = 0;


        for(int j=0; j<arrayMessage[0].length; j++) {

            //System.out.println();

            for(int i=0; i<arrayMessage.length; i++) {
                if( iC < message.length() ) {
                    arrayMessage[i][j] = message.substring(iC, iC + 1);
                    //System.out.print("("+i+","+j+"):"+arrayMessage[i][j]+" ");
                    iC++;
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
                }
            }
        }

        //System.out.println();

        // Step 2: invert the column order mapping
        // newOrderColumn[originalCol] = sortedIndex → allows row-by-row grid read
        int [] newOrderColumn = new int [orderColumn.length];
        for(int i=0; i<newOrderColumn.length; i++) {
            for(int j=0; j<orderColumn.length; j++) {
                if( orderColumn[j] == i ){
                    newOrderColumn[i] = j;
                    //System.out.print("("+i+"):"+j+" ");
                }
            }
        }

        //System.out.println();

        orderColumn = newOrderColumn;

        cipherMessage = "";

        // Step 3: read grid row-by-row in the inverted column order → fractionated pairs
        String [] arrayCode = new String[ arrayMessage.length * arrayMessage[0].length ];
        int indexCode = 0;

        for(int i=0; i<arrayMessage.length; i++) {
            for(int j=0; j<arrayMessage[0].length; j++) {
                arrayCode[indexCode] = arrayMessage[i][ orderColumn[j] ] ;
                //System.out.print( arrayCode[indexCode] );
                indexCode++;
            }
        }

        // Step 4: convert pairs back to plaintext characters
        // Stop when either coordinate in a pair is the 'z' padding marker
        for(int i=0; i<arrayCode.length; ) {
            if ( arrayCode[i].compareTo( "z" ) == 0 || arrayCode[i+1].compareTo( "z" ) == 0 )break;
            cipherMessage = cipherMessage.concat( arrayAdfgx[ lookForNumber( arrayCode[i] ) ][ lookForNumber( arrayCode[i+1] ) ] );
            i += 2;
        }

        //System.out.println();

        return cipherMessage;
    }

    /**
     * Returns the index of a coordinate letter in indexArray (a/d/f/g/v/x → 0–5).
     * Used to convert a pair of coordinate letters back into a grid position.
     */
    private int lookForNumber( String letter ) {

        int position;

        for(int i=0; i<this.indexArray.length; i++) {
            if( this.indexArray[i].compareTo(letter) == 0) {
                position = i;
                return position;
            }
        }

        return -1;
    }

    /**
     * Strips characters not present in the substitution grid from the message.
     * Only characters found in arrayAdfgx (a–z + 0–9) survive.
     */
    private String cleanMessage( String message ) {

        String cleanMessage = "";

        for(int i=0; i<message.length(); i++) {
            if ( lookForLetter( message.substring(i,i+1).toLowerCase() ) != null ) {
                cleanMessage = cleanMessage.concat( message.substring(i,i+1).toLowerCase() );
            }
        }

        return cleanMessage;
    }

    /**
     * Cleans and deduplicates the key word (same logic as columnTransposition).
     * Keeps only characters present in the grid alphabet.
     */
    private String cleanPassword( String password ) {

        String cleanPassword = "";

        for(int i = 0; i < password.length(); i++) {

            if ( cleanPassword.length() == 0 ) {
                cleanPassword = cleanPassword.concat( password.substring(i,i+1).toLowerCase() );
                //System.out.println("Codigo password: " + myPassword.substring(i,i+1).codePointAt(0) );
            }

            else {
                boolean jumpChar = false;

                for(int j=0; j < cleanPassword.length(); j++) {

                    if( cleanPassword.substring(j,j+1).compareTo( password.substring(i,i+1).toLowerCase() ) == 0 ) {
                        jumpChar = true;
                        break;
                    }
                }

                if(!jumpChar) {
                    cleanPassword = cleanPassword.concat( password.substring(i,i+1).toLowerCase() );
                    //System.out.println("Codigo password: " + myPassword.substring(i,i+1).codePointAt(0) );
                }
            }
        }

        cleanPassword = cleanMessage( cleanPassword );
        return cleanPassword;
    }

    /**
     * Finds the [row, col] coordinates of a character in the 6×6 substitution grid.
     *
     * @param letter A single-character string to locate
     * @return int[]{row, col} or null if not found
     */
    private int [] lookForLetter( String letter ) {

        for(int i=0; i<this.arrayAdfgx.length;i++) {

            for(int j=0; j<this.arrayAdfgx[0].length; j++) {
                if( this.arrayAdfgx[i][j].compareTo(letter) == 0 ) {
                    int position [] = {i, j};
                    return position;
                }
            }
        }

        return null;
    }
}
