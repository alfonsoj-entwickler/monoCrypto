package systemcryptography.monocrypto;

import android.util.Base64;
import android.util.Log;

public class vermanCipher {

    private String password;
    private final boolean needKey = true;

    private final String [] arrayAlphabetExt = {
            "!", " ", "\"", "#", "$","%","&","'","!", ")",
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
        this.password = cleanMessage( password );
    }

    public boolean getNeedKey() {
        return this.needKey;
    }

    private int lookForChar(String myChar) {
        for(int i=0; i<this.arrayAlphabetExt.length; i++) {
            if( this.arrayAlphabetExt[i].compareTo(myChar) == 0 )
                return i;
        }

        return -1;
    }

    private String cleanMessage( String message ) {
        String cleanMessage = "";
        for(int i=0; i<message.length(); i++) {
            if( lookForChar(message.substring(i, i + 1)) >= 0 ) {
                cleanMessage = cleanMessage.concat( message.substring( i,i+1 ) );
            }
        }

        return cleanMessage;
    }

    public String doCipher(String message) {

        message = cleanMessage( message );
        String  cipherMessage;

        //for(int i=0; i<message.length(); i++) {
            // operacion xor se sale de rango, el array tiene un intervalo menor que la operacion xor de dos bytes
            //if( i < message.length() && i < this.password.length() ) {

                //Log.i( "operacion", "Operacion: "+lookForChar( this.password.substring( i,i+1 ) )+" xor "+lookForChar( message.substring( i,i+1 ) )+": "+(lookForChar( this.password.substring( i,i+1 ) ) ^ lookForChar( message.substring( i,i+1 ) ) ) );

                //if( ( this.arrayAlphabetExt.length ) < (lookForChar( arrayPassword[i] ) ^ lookForChar( arrayMessage[i] ) ) ) continue;
                //cipherMessage = cipherMessage.concat( this.arrayAlphabetExt[ ( lookForChar( this.password.substring( i,i+1 ) ) ^ lookForChar( message.substring( i,i+1 ) ) ) % arrayAlphabetExt.length ] );


                byte [] bytePassword = this.password.getBytes();
                byte [] byteMessage = message.getBytes();
                byte [] result;
                if( bytePassword.length > byteMessage.length ) {
                    result = new byte[ byteMessage.length ];
                }
                else {
                    result = new byte[ bytePassword.length ];
                }

                for( int j=0; j<result.length; j++ ) {
                    if( j < byteMessage.length && j < bytePassword.length )
                        result[ j ] = (byte)( bytePassword[j] ^ byteMessage[j] );
                }
                cipherMessage = Base64.encodeToString( result, Base64.DEFAULT );

            //}
        //}

        return cipherMessage;
    }

    public String doDecoding(String message) {

        String  plainMessage;

        byte [] bytePassword = this.password.getBytes();
        byte [] byteMessage = Base64.decode( message.getBytes(), Base64.DEFAULT );
        byte [] result;
        if( bytePassword.length > byteMessage.length ) {
            result = new byte[ byteMessage.length ];
        }
        else {
            result = new byte[ bytePassword.length ];
        }

        for( int j=0; j<result.length; j++ ) {
            if( j < byteMessage.length && j < bytePassword.length )
                result[ j ] = (byte) (bytePassword[j] ^ byteMessage[j] );
        }
        plainMessage = new String( result );

        return plainMessage;
    }
}
