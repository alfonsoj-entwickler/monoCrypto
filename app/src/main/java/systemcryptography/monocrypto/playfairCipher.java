package systemcryptography.monocrypto;


/**
 * Playfair Cipher — digraph substitution cipher using a 5×5 key matrix.
 *
 * The Playfair cipher encrypts pairs of letters (digraphs) rather than single
 * characters. The 5×5 matrix (25 cells) uses the 25-letter alphabet a–z with
 * 'j' omitted (since it merges j and i).
 *
 * Key matrix construction:
 *   1. Remove duplicate letters from the password.
 *   2. Fill the matrix left-to-right with unique password letters first,
 *      then the remaining alphabet letters not already present.
 *
 * Message preparation (paddingMessage):
 *   - Convert to lowercase and strip non-alpha characters.
 *   - If two consecutive identical letters appear in a pair, insert 'x' between them.
 *   - If the message has an odd length, append 'x'.
 *
 * Encryption rules for each digraph [L1, L2]:
 *   - Same row:    replace each letter with the one immediately to its RIGHT (wrapping).
 *   - Same column: replace each letter with the one immediately BELOW it (wrapping).
 *   - Rectangle:   L1 → same row, column of L2; L2 → same row, column of L1.
 *
 * Decryption rules (reverse):
 *   - Same row:    shift LEFT instead of right.
 *   - Same column: shift UP instead of down.
 *   - Rectangle:   same swap as encryption (it is its own inverse).
 *
 * After decryption, padding 'x' characters inserted during encoding are removed
 * where the surrounding context confirms they were padding (not original data).
 */
public class playfairCipher {

    private String password;
    private final boolean needKey = true;

    // Default 5×5 Playfair grid (standard a–z minus 'j')
    private final String [][] arrayPlayfair = {
            {"a", "b", "c", "d", "e"},
            {"f", "g", "h", "i", "k"},
            {"l", "m", "n", "o", "p"},
            {"q", "r", "s", "t", "u"},
            {"v", "w", "x", "y", "z"},
    };

    // Password-keyed 5×5 matrix, built in addPassword() before each operation
    private String [][] myAlphabet;

    public  void setPassword( String password ) {
        this.password = password;
    }

    public boolean getNeedKey() {
        return this.needKey;
    }

    /**
     * Finds the [row, col] position of a letter in the default Playfair grid.
     * Used during password-keyed matrix construction.
     *
     * @return int[]{row, col} or null if not found
     */
    private int [] lookForLetter( String letter ) {

        for(int i=0; i<this.arrayPlayfair.length;i++) {

            for(int j=0; j<this.arrayPlayfair[0].length; j++) {
                if(this.arrayPlayfair[i][j].compareTo(letter) == 0) {
                    int [] position = {i, j};
                    return position;
                }
            }
        }

        return null;
    }

    /**
     * Finds the [row, col] position of a letter in the password-keyed matrix.
     * Used during encryption and decryption to look up digraph positions.
     *
     * @return int[]{row, col} or null if not found
     */
    private int [] lookForMyAlphabet( String letter ) {

        for(int i=0; i<this.myAlphabet.length;i++) {

            for(int j=0; j<this.myAlphabet[0].length; j++) {
                if(this.myAlphabet[i][j].compareTo(letter) == 0) {
                    int [] position = {i, j};
                    return position;
                }
            }
        }

        return null;
    }

    /**
     * Builds the 5×5 key matrix from the cleaned password.
     *
     * Algorithm:
     *   1. Fill positions with deduplicated password characters.
     *   2. Continue filling with alphabet characters not already in the password,
     *      in standard a–z (minus j) order.
     *
     * @param password The raw user-supplied keyword
     * @return The 5×5 key matrix as a 2D String array
     */
    private String [][] addPassword( String password ) {

        String myPassword = cleanPassword( password );
        String [][] myPlayFair = new String [ arrayPlayfair.length ][ arrayPlayfair[0].length ];
        int row = 0;
        int column = 0;

        // Place password characters first
        for(int i=0; i<myPassword.length(); i++) {
            if( column == myPlayFair[0].length ) {
                row++;
                column = 0;
                System.out.println();
            }
            myPlayFair[row][column] = myPassword.substring( i,i+1 );
            System.out.print("("+row+","+column+"):"+myPlayFair[row][column]+" ");
            column++;
        }

        boolean addLetter = true;

        // Fill remaining cells with alphabet letters not already in the password
        for(int i=0; i<arrayPlayfair.length; i++) {
            for(int j=0; j<arrayPlayfair[0].length; j++) {

                for(int k=0; k<myPassword.length(); k++) {
                    if( arrayPlayfair[i][j].compareTo( myPassword.substring( k,k+1 ) ) == 0 )
                        addLetter = false;
                }

                if( column == myPlayFair[0].length ) {
                    row++;
                    column = 0;
                    System.out.println();
                }

                if( addLetter ) {
                    myPlayFair[row][column] = arrayPlayfair[i][j];
                    System.out.print("("+row+","+column+"):"+myPlayFair[row][column]+" ");
                    column++;
                }
                addLetter = true;
            }
        }

        return myPlayFair;


    }

    /**
     * Prepares a message for Playfair encryption:
     *   - Strips non-alphabetic characters and lowercases.
     *   - Inserts 'x' between identical consecutive letters in a pair.
     *   - Appends 'x' if the final message length is odd.
     *
     * @param message Raw plaintext string
     * @return Padded, cleaned message ready for digraph processing
     */
    private String paddingMessage( String message ) {
        String paddingMessage = "";

        message = cleanMessage( message );

        for(int i=0; i<message.length();) {

            if( i >= ( message.length() - 1 ) ) {
                // Last character: add as-is (trailing 'x' appended below if needed)
                paddingMessage = paddingMessage.concat( message.substring( i,i+1 ) );
            }
            else if( message.substring( i,i+1 ).compareTo( message.substring( i+1,i+2 ) ) == 0 ) {
                // Two consecutive identical letters: insert 'x' as a separator
                paddingMessage = paddingMessage.concat( message.substring( i,i+1 ) + "x" );
                message = message.substring(0,i+1).concat( "x" + message.substring( i+1,message.length() ) );
            }
            else {
                // Normal pair: add both letters as a digraph
                paddingMessage = paddingMessage.concat( message.substring( i,i+1 ) + message.substring( i+1,i+2 ) );
            }

            i += 2;
        }

        // Ensure even length (required for complete digraphs)
        if( (paddingMessage.length()%2) != 0 )
            paddingMessage = paddingMessage.concat( "x" );

        return paddingMessage;

    }

    /**
     * Keeps only lowercase letters present in the Playfair grid (a–z minus j).
     */
    private String cleanMessage( String message ) {

        String cleanMessage = "";

        for(int i=0; i<message.length(); i++) {
            if( lookForLetter( message.substring( i,i+1 ).toLowerCase() ) != null) {
                cleanMessage = cleanMessage.concat( message.substring( i,i+1 ).toLowerCase() );
            }
        }

        return cleanMessage;
    }

    /**
     * Cleans and deduplicates the password for use in key matrix construction.
     * Spaces and characters outside the Playfair alphabet are discarded.
     *
     * @param password The raw keyword
     * @return Lowercase, deduplicated, alphabet-filtered password
     */
    private String cleanPassword( String password ) {

        String myPassword = password;
        String cleanPassword = "";


        for(int i = 0; i < myPassword.length(); i++) {

            if ( cleanPassword.length() == 0 ) {
                cleanPassword = cleanPassword.concat( myPassword.substring(i,i+1).toLowerCase() );
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
                }
            }
        }

        // Further filter: keep only letters that appear in the Playfair grid
        cleanPassword = cleanMessage( cleanPassword );
        return cleanPassword;
    }

    /**
     * Encrypts a message using the Playfair cipher.
     *
     * For each digraph [L1, L2] located at positions (r1,c1) and (r2,c2):
     *   - Same row    (r1==r2): shift each column +1 (wrap at 5)
     *   - Same column (c1==c2): shift each row    +1 (wrap at 5)
     *   - Rectangle   (r1!=r2 && c1!=c2): swap columns — L1→(r1,c2), L2→(r2,c1)
     *
     * @param message Plaintext string
     * @return Ciphertext string
     */
    public String doCipher ( String message ) {

        message = cleanMessage( message );
        message = paddingMessage( message );
        this.myAlphabet = addPassword( this.password );
        String cipherMessage = "";
        int [] letterOne;
        int [] letterTwo;

        for(int i=0; i<message.length();) {
            letterOne = lookForMyAlphabet( message.substring(i,i+1) );
            letterTwo = lookForMyAlphabet( message.substring(i+1,i+2) );

            // Same row: shift both letters one column to the right (wrap around)
            if( letterOne[0] == letterTwo[0] ) {
                if( (letterOne[1] + 1) >= 5 ) {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterOne[0] ][0] );
                }
                else {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterOne[0] ][ letterOne[1] + 1 ] );
                }

                if( (letterTwo[1] + 1) >= 5 ) {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterTwo[0] ][0] );
                }
                else {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterTwo[0] ][ letterTwo[1] + 1 ] );
                }
            }
            // Same column: shift both letters one row down (wrap around)
            else if( letterOne[1] == letterTwo[1] ) {
                if( ( letterOne[0] + 1 ) >=5 ) {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ 0 ][ letterOne[1] ] );
                }
                else {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterOne[0] + 1 ][ letterOne[1] ] );
                }
                if( ( letterTwo[0] + 1 ) >=5 ) {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ 0 ][ letterTwo[1] ] );
                }
                else {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterTwo[0] + 1 ][ letterTwo[1] ] );
                }

            }
            // Rectangle: each letter moves to the other letter's column, same row
            else if( letterOne[0] != letterTwo[0] && letterOne[1] != letterTwo[1] ) {
                cipherMessage = cipherMessage.concat( this.myAlphabet[ letterOne[0] ][ letterTwo[1] ] );
                cipherMessage = cipherMessage.concat( this.myAlphabet[ letterTwo[0] ][ letterOne[1] ] );
            }

            i += 2;
        }

        return cipherMessage;
    }

    /**
     * Decrypts a Playfair-encrypted message.
     *
     * Applies the inverse rules:
     *   - Same row:    shift each letter one column to the LEFT  (wrap at 0)
     *   - Same column: shift each letter one row UP              (wrap at 0)
     *   - Rectangle:   same swap as encryption (self-inverse)
     *
     * After decoding, removes 'x' padding characters that were inserted during
     * encoding — only removes 'x' that was not flanked by the same character
     * (i.e., it was a filler, not original data).
     *
     * @param message Ciphertext string
     * @return Decrypted plaintext string
     */
    public String doDecoding ( String message ) {

        message = cleanMessage( message );
        message = paddingMessage( message );
        this.myAlphabet = addPassword( this.password );
        String cipherMessage = "";
        int [] letterOne;
        int [] letterTwo;

        for(int i=0; i<message.length();) {
            letterOne = lookForMyAlphabet( message.substring(i,i+1) );
            letterTwo = lookForMyAlphabet( message.substring(i+1,i+2) );

            // Same row: shift left (inverse of encrypt's shift right)
            if( letterOne[0] == letterTwo[0] ) {
                if( (letterOne[1] - 1) < 0 ) {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterOne[0] ][4] );
                }
                else {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterOne[0] ][ letterOne[1] - 1 ] );
                }

                if( (letterTwo[1] - 1) < 0 ) {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterTwo[0] ][4] );
                }
                else {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterTwo[0] ][ letterTwo[1] - 1 ] );
                }
            }
            // Same column: shift up (inverse of encrypt's shift down)
            else if( letterOne[1] == letterTwo[1] ) {
                if( ( letterOne[0] - 1 ) < 0 ) {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ 4 ][ letterOne[1] ] );
                }
                else {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterOne[0] - 1 ][ letterOne[1] ] );
                }
                if( ( letterTwo[0] - 1 ) < 0 ) {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ 4 ][ letterTwo[1] ] );
                }
                else {
                    cipherMessage = cipherMessage.concat( this.myAlphabet[ letterTwo[0] - 1 ][ letterTwo[1] ] );
                }

            }
            // Rectangle: same column swap as encryption (self-inverse)
            else if( letterOne[0] != letterTwo[0] && letterOne[1] != letterTwo[1] ) {
                cipherMessage = cipherMessage.concat( this.myAlphabet[ letterOne[0] ][ letterTwo[1] ] );
                cipherMessage = cipherMessage.concat( this.myAlphabet[ letterTwo[0] ][ letterOne[1] ] );
                //cipherMessage = cipherMessage.concat();
            }

            i += 2;
        }

        // Remove 'x' padding: keep 'x' only if the adjacent chars are different
        // (meaning it was genuine data, not a filler inserted between repeated letters)
        String cleanCipherMessage = "";
        for(int i=0; i<cipherMessage.length(); i++) {
            if( cipherMessage.substring(i,i+1).compareTo("x") != 0 ){
                cleanCipherMessage = cleanCipherMessage.concat( cipherMessage.substring(i,i+1) );
            }
            else {
                if( (i+2) < cipherMessage.length() && ( i-1 ) > 0 ) {
                    if( cipherMessage.substring(i-1,i).compareTo( cipherMessage.substring(i+1,i+2) ) != 0 )
                        cleanCipherMessage = cleanCipherMessage.concat( cipherMessage.substring(i,i+1) );
                }
            }
        }

        cipherMessage = cleanCipherMessage;

        return cipherMessage;
    }


}
