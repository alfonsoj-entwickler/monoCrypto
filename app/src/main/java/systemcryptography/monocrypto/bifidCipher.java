package systemcryptography.monocrypto;


public class bifidCipher extends classicCipher {

    private final boolean needKey = false;
    
    private final String [][] arrayBifidAlphabet = {
            {"b", "g", "w", "k", "z"},
            {"q", "p", "n", "d", "s"},
            {"i", "o", "a", "x", "e"},
            {"f", "c", "l", "u", "m"},
            {"t", "h", "y", "v", "r"},
    };

    private final String [] vectorBifidalphabet = {
            "b", "g", "w", "k", "z",
            "q", "p", "n", "d", "s",
            "i", "o", "a", "x", "e",
            "f", "c", "l", "u", "m",
            "t", "h", "y", "v", "r",
    };

    public boolean getNeedKey() {
        return this.needKey;
    }

    private int lookForLetter( String letter ) {

        for(int i=0; i<vectorBifidalphabet.length; i++) {
            if( letter.compareTo( vectorBifidalphabet[i] ) == 0 ) return i;
        }

        return -1;
    }

    private String cleanMessage( String message ) {

        String cleanMessage = "";

        for(int i=0; i<message.length(); i++) {
            if ( lookForLetter( message.substring(i,i+1).toLowerCase() ) >= 0 ) {
                cleanMessage = cleanMessage.concat( message.substring(i,i+1).toLowerCase() );
            }
        }

        // relleno final si hiceiera falta

        if( (cleanMessage.length() % 2) > 0 )  {
            cleanMessage = cleanMessage.concat("x");
        }
        return cleanMessage;
    }

    private int [] getPositionalphabet( String letter ) {

        int [] position = new int [2];

        for(int i=0; i<arrayBifidAlphabet.length; i++) {
            for(int j=0; j<arrayBifidAlphabet[0].length; j++) {
                if (arrayBifidAlphabet[i][j].compareTo(letter) == 0) {
                    position [0] = i;
                    position [1] = j;
                    return position;
                }
            }
        }

        return position;
    }

    public String doCipher( String message ) {

        String cipherMessage = "";
        int [] letter;
        message = cleanMessage(message);
        int [][] positions = new int [2][message.length()];

        for(int i=0; i<message.length(); i++ ) {
            letter = getPositionalphabet( message.substring(i,i+1) );
            positions[0][i] = letter[0];
            positions[1][i] = letter[1];

        }
        for(int k=0; k<2; k++) {
            for(int j=0; j<positions[k].length;) {
                cipherMessage = cipherMessage.concat( arrayBifidAlphabet [ positions[k][j] ] [ positions[k][j+1] ] );
                j += 2;
            }
        }

        return cipherMessage;
    }

    public String doDecoding( String message ) {

        String cipherMessage = "";
        int [] letter;
        message = cleanMessage(message);
        int [][] positions = new int [2][message.length()];
        int indexR = 0;
        int indexC = 0;

        for(int i=0; i<message.length(); i++ ) {
            letter = getPositionalphabet( message.substring(i,i+1) );

            if( indexC >= positions[0].length  ) {
                indexR++;
                indexC = 0;
            }

            positions[indexR][indexC] = letter[0];
            indexC++;
            positions[indexR][indexC] = letter[1];
            indexC++;
        }

        for(int j=0; j<positions[0].length;j++) {
            cipherMessage = cipherMessage.concat( arrayBifidAlphabet [ positions[0][j] ] [ positions[1][j] ] );
        }

        for(int i=cipherMessage.length(); i>0; i--) {

            if( cipherMessage.substring(i-1,i).compareTo( "x" ) != 0 ) {
                cipherMessage = cipherMessage.substring(0, i);
                break;
            }
        }


        return cipherMessage;
    }


}
