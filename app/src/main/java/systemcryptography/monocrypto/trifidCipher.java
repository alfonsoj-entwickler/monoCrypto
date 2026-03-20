package systemcryptography.monocrypto;

public class trifidCipher extends classicCipher {

    private final int [][] coordinates = {
            {1,1,1,111}, {1,1,2,112}, {1,1,3,113},
            {1,2,1,121}, {1,2,2,122}, {1,2,3,123},
            {1,3,1,131}, {1,3,2,132}, {1,3,3,133},
            {2,1,1,211}, {2,1,2,212}, {2,1,3,213},
            {2,2,1,221}, {2,2,2,222}, {2,2,3,223},
            {2,3,1,231}, {2,3,2,232}, {2,3,3,233},
            {3,1,1,311}, {3,1,2,312}, {3,1,3,313},
            {3,2,1,321}, {3,2,2,322}, {3,2,3,323},
            {3,3,1,331}, {3,3,2,332}, {3,3,3,333}
    };

    private final String [] arrayAlphabetTrifid = {
            "f", "r", "y", "j", "x", "b", "o",
            "c", "s", "v", "g", "m", "z", "d",
            "w", "l", "p", "t", "e", "n", ".",
            "u", "h", "k", "q", "a", "i"
    };

    private final boolean needKey = false;

    public boolean getNeedKey() {
        return this.needKey;
    }

    private int lookForLetter( String letter ) {

        for(int i=0; i<arrayAlphabetTrifid.length; i++) {
            if( letter.compareTo( arrayAlphabetTrifid[i] ) == 0 ) return i;
        }

        return -1;
    }

    private int lookForNumber( int myNumber ) {
        for( int i=0; i<coordinates.length; i++ ) {
            if( myNumber == coordinates[i][3] )
                return i;
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

        return cleanMessage;
    }

    public String doCipher( String message ) {
        String cipherMessage = "";


        message = cleanMessage( message );
        int [] lettersPosition = new int [message.length()];

        for(int i=0; i<message.length(); i++) {
            lettersPosition[i] = lookForLetter( message.substring( i,i+1 ) );
        }

        int [] cipherPosition = new int [lettersPosition.length * 3];
        int arrayPosition = 0;


        for(int k=0; k<3; k++) {
            for(int j=0; j<lettersPosition.length; j++) {
                cipherPosition[arrayPosition] = coordinates [ lettersPosition[j] ][k];
                arrayPosition++;

            }
        }

        for(int t=0;t<cipherPosition.length;) {
            String cipherLetter = arrayAlphabetTrifid[ lookForNumber( (cipherPosition[t] * 100) + ( cipherPosition[t+1] *  10) + cipherPosition[t+2] ) ];
            cipherMessage = cipherMessage.concat(cipherLetter);
            t +=3;
        }


        return cipherMessage;
    }

    public String doDecoding( String message ) {
        String cipherMessage = "";


        message = cleanMessage( message );
        int [] lettersPosition = new int [message.length()];

        for(int i=0; i<message.length(); i++) {
            lettersPosition[i] = lookForLetter( message.substring( i,i+1 ) );
        }

        int [][] cipherPosition = new int [3][lettersPosition.length];
        int indexR = 0;
        int indexC = 0;


        for(int j=0; j<lettersPosition.length; j++) {

            for( int i=0; i<3; i++ ) {

                if( indexC >= lettersPosition.length ) {
                    indexC = 0;
                    indexR++;
                }

                cipherPosition[indexR][indexC] = coordinates [ lettersPosition[j] ][i];
                indexC++;
            }

        }


        for(int t=0;t<cipherPosition[0].length;t++) {
            String cipherLetter = arrayAlphabetTrifid[ lookForNumber( (cipherPosition[0][t] * 100) + ( cipherPosition[1][t] *  10) + cipherPosition[2][t] ) ];
            cipherMessage = cipherMessage.concat(cipherLetter);
        }

        return cipherMessage;
    }
}
