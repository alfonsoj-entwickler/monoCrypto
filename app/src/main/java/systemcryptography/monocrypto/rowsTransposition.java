package systemcryptography.monocrypto;

public class rowsTransposition {

    private int rowPassword;
    private String password;
    private final boolean needKey = true;

    private final String [] arrayAlphabet = {
            "a", "b", "c", "d", "e", "f",
            "g", "h", "i", "j", "k", "l",
            "m", "n", "o", "p", "q",
            "r", "s", "t", "u", "v", "w",
            "x", "y", "z"
    };

    public  void setPassword( int password ) {
        this.rowPassword = password;
    }

    public  void setPassword( String password ) {
        this.password = cleanPassword( password );
        this.rowPassword = this.password.length();
    }

    public boolean getNeedKey() {
        return this.needKey;
    }

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

        cleanPassword = cleanMessage( cleanPassword );
        return cleanPassword;
    }

    private int lookForLetter( String letter ) {

        for(int i=0; i<this.arrayAlphabet.length;i++) {

            if( this.arrayAlphabet[i].compareTo(letter) == 0 ) {
                int  position = i;
                return position;
            }

        }

        return -1;
    }

    public String cleanMessage( String message ) {

        String cleanMessage = "";

        for(int i=0; i<message.length(); i++) {
            if ( lookForLetter( message.substring(i,i+1).toLowerCase() ) != -1 ) {
                cleanMessage = cleanMessage.concat( message.substring(i,i+1).toLowerCase() );
            }
        }

        return cleanMessage;
    }

    public String doDecoding(String message) {

        String cipherMessage = "";

        int columns = (int)Math.ceil( new Double(message.length() - 1) / new Double(this.rowPassword) );

        String [][] arrayCipher = new String [this.rowPassword][columns];
        int number = 0;
        for(int i=0; i<arrayCipher.length; i++) {

            for(int j=0; j<arrayCipher[0].length; j++) {
                if( number >= message.length() ) {
                    arrayCipher [i][j] = "x";
                }
                else {
                    arrayCipher [i][j] = message.substring( number, number+1 );
                    number++;
                }
            }
        }

        int [] orderRow = new int[ this.password.length() ];

        int indexOrders = 0;

        for( int j=97; j<122; j++ ) {

            for(int h=0; h<this.password.length(); h++) {

                if( j == this.password.substring(h,h+1).codePointAt(0) ) {
                    orderRow[indexOrders] = h;
                    indexOrders++;
                }
            }
        }

        int [] newOrderRow = new int [orderRow.length];
        for(int i=0; i<newOrderRow.length; i++) {
            for(int j=0; j<orderRow.length; j++) {
                if( orderRow[j] == i ){
                    newOrderRow[i] = j;
                }
            }
        }

        orderRow = newOrderRow;

        for( int c=0; c<arrayCipher[0].length; c++ ) {
            for( int r=0; r<arrayCipher.length; r++ ) {

                cipherMessage = cipherMessage.concat(arrayCipher[orderRow[r]][c]);
            }
        }

        for(int g=cipherMessage.length(); g>0; g--) {
            if( cipherMessage.substring(g-1, g).compareTo("x") != 0 ) {
                cipherMessage = cipherMessage.substring(0, g);
                break;
            }
        }
        System.out.println();
        return cipherMessage;
    }

    public String doCipher(String message) {

        String cipherMessage = "";
        int columns = (int)Math.ceil( new Double(message.length() - 1) / new Double(this.rowPassword) );

        String [][] arrayCipher = new String [this.rowPassword][columns];

        int number = 0;
        for(int i=0; i<arrayCipher[0].length; i++) {
            for(int j=0; j<arrayCipher.length; j++) {
                if( number >= message.length() ) {
                    arrayCipher [j][i] = "x";
                }
                else {
                    arrayCipher [j][i] = message.substring(number,number+1);
                    number++;
                }
            }
        }

        int [] orderRow = new int[ this.password.length() ];
        int indexOrders = 0;

        for( int j=97; j<122; j++ ) {

            for(int h=0; h<this.password.length(); h++) {

                if( j == this.password.substring(h,h+1).codePointAt(0) ) {
                    orderRow[indexOrders] = h;
                    indexOrders++;
                }
            }
        }

        for(int c=0; c<arrayCipher.length; c++) {
            for(int r=0; r<arrayCipher[0].length; r++) {
                cipherMessage = cipherMessage.concat(arrayCipher[orderRow[c]][r]);
            }
        }
        return cipherMessage;
    }
}
