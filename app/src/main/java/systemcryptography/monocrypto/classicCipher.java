package systemcryptography.monocrypto;

public class classicCipher {

    private final String [] arrayAlphabet = {
            "a", "b", "c", "d", "e", "f",
            "g", "h", "i", "j", "k","l",
            "m", "n", "o", "p","q",
            "r", "s", "t", "u","v","w",
            "x", "y", "z"
    };

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

    private final String [][] arrayAlphabetForBifid = {
            {"b", "g", "w", "k", "z"},
            {"q", "p", "n", "d", "s"},
            {"i", "o", "a", "x", "e"},
            {"f", "c", "l", "u", "m"},
            {"t", "h", "y", "v", "r"},
    };

    public int lookForChar(String myChar) {
        for(int i=0; i<this.arrayAlphabet.length; i++) {
            if( this.arrayAlphabet[i].compareTo(myChar) == 0 )
                return i;
        }

        return -1;
    }


}
