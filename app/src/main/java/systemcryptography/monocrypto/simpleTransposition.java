package systemcryptography.monocrypto;


public class simpleTransposition {

    private final boolean needKey = false;

    public boolean getNeedKey() {
        return this.needKey;
    }

    public String doCipher( String message ) {
        message = message.trim();
        String [] arrayMessage = message.split("");
        String cipherMessage = "";

        for(int i=arrayMessage.length-1; i>0; i--) {
            cipherMessage = cipherMessage.concat(arrayMessage[i]);
        }

        return cipherMessage;
    }

    public String doDecoding(String message) {
        return doCipher(message);
    }
}
