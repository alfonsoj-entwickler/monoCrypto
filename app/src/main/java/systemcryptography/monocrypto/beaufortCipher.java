package systemcryptography.monocrypto;


public class beaufortCipher {

    private String password;
    private final boolean needKey = true;

    /*private final String [] arrayAlphabet = {
            "a", "b", "c", "d", "e", "f",
            "g", "h", "i", "j", "k","l",
            "m", "n",  "o", "p","q",
            "r", "s", "t", "u","v","w",
            "x", "y", "z"
    };*/


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

    public  void setPassword( String password ) {
        this.password = cleandMessage( password );
    }

    public boolean getNeedKey() {
        return this.needKey;
    }

    private String cleandMessage( String message ) {
        String cleanMessage = "";
        for( int i=0; i<message.length(); i++ ) {
            if( lookForChar( message.substring(i, i + 1) ) >= 0 ) {
                cleanMessage = cleanMessage.concat( message.substring( i,i+1 ) );
            }
        }

        return cleanMessage;
    }

    private int lookForChar(String myChar) {
        for(int i=0; i<this.arrayAlphabetExt.length; i++) {
            if( this.arrayAlphabetExt[i].compareTo(myChar) == 0 )
                return i;
        }
        return -1;
    }

    public String doCipher(String message) {

        message = cleandMessage( message );
        String  cipherMessage = "";
        int indexPassword = 0;
        int result;

        for(int i=0; i<message.length(); i++) {

            if( lookForChar( message.substring( i,i+1 ) ) != -1 ) {

                if( indexPassword >= this.password.length() ) indexPassword = 0;

                result = ( ( (this.arrayAlphabetExt.length - 1) - lookForChar( message.substring( i,i+1 ) ) ) + ( lookForChar(this.password.substring(indexPassword, indexPassword+1)) + 1 ) );
                //if(result < 0) result = result + this.arrayAlphabetExt.length;
                cipherMessage = cipherMessage.concat( this.arrayAlphabetExt[ result % this.arrayAlphabetExt.length ] );

                indexPassword++;
            }
        }

        return cipherMessage;
    }

    public String doDecoding(String message) {
        return doCipher(message);
    }

}
