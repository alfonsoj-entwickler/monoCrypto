package systemcryptography.monocrypto;


import android.util.Log;

public class polybiosCipher {

    private final String [] rowChar = {"a", "b", "c", "d", "e", "f", "g", "h", "j", "k"};
    private final String [] rowNumber = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
    private final boolean needKey = false;

    private final String [][] arrayPolybios1 = {
            {" ", "!", "\"", "#", "$","%","&","'","!", ")"},
            {"*", "+", ",", "-", ".", "/", "0", "1", "2", "3"},
            {"4", "5", "6", "7", "8", "9", ":", ";", "<", "="},
            {">", "?", "@", "A", "B", "C", "D", "E", "F", "G"},
            {"H", "I", "J", "K", "L", "M", "N", "O", "P", "Q"},
            {"R", "S", "T", "U", "V", "W", "X", "Y", "Z", "["},
            {"\\", "]", "^", "_", "`", "a", "b", "c", "d", "e"},
            {"f", "g", "h", "i", "j", "k", "l", "m", "n", "o"},
            {"p", "q", "r", "s", "t", "u", "v", "w", "x", "y"},
            {"z", "{", "|", "}", "~", "\n", "\t", "\r", "\f", "\b"}
    };

    private final String [][] arrayPolybios2 = {
            {"a", "b", "c", "d", "e"},
            {"f", "g", "h", "ij", "k"},
            {"l", "m", "n", "o", "o"},
            {"q", "r", "s", "t", "u"},
            {"v", "w", "x", "y", "z"},
    };

    public boolean getNeedKey() {
        return this.needKey;
    }

    public String doCipher(String message) {
        String [] arrayMessage = message.split("");
        String cipherMessage = "";

        for(int i=0; i<arrayMessage.length; i++) {
            int [] positions = getPositionArrayPolybios(arrayMessage[i]);
            if(positions != null) {
                cipherMessage = cipherMessage.concat( this.rowChar[positions[0]].concat( this.rowChar[positions[1]] ) );
            }

        }

        return cipherMessage;
    }

    public String doDecoding(String message) {
        String [] arrayMessage = message.split("");
        int [] index = new int [arrayMessage.length - 1];
        String plainText = "";

        for(int i=1; i<arrayMessage.length; i++) {
            index[i-1] = getPositionArrayRow( arrayMessage[i] );
        }

        for(int j=0; j<index.length;) {
            plainText = plainText.concat( this.arrayPolybios1[index[j]][index[j+1]] );
            j+=2;
        }

        return plainText;
    }

    private int getPositionArrayRow(String letter) {

        for(int i=0; i<this.rowChar.length; i++) {
            if( this.rowChar[i].compareTo(letter) == 0) {
                int position = i;
                return position;
            }
        }
        Log.i( "error", letter );
        return -1;
    }

    private int [] getPositionArrayPolybios( String letter ) {

        for(int i=0; i<this.arrayPolybios1.length;i++) {

            for(int j=0; j<this.arrayPolybios1[0].length; j++) {
                if( this.arrayPolybios1[i][j].compareTo(letter) == 0 ) {
                    int [] position = {i, j};
                    return position;
                }
            }
        }

        return null;
    }
}
