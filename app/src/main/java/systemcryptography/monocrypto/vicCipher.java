package systemcryptography.monocrypto;


public class vicCipher {

    private final String [] arrayMain = {
            "e", "t", null, "a", "o", "n", null, "r", "i", "s"
    };

    private final String [] arrayDos = {
            "b", "c", "d", "f", "g", "h", "j", "k", "l", "m"
    };

    private final String [] arraySeis = {
            "p", "q", "/", "u", "v", "w", "x", "y", "z", "."
    };

    private final String [][] arrayVicCipher = {
            {"e", "t", null, "a", "o", "n", null, "r", "i", "s"},
            {"b", "c", "d", "f", "g", "h", "j", "k", "l", "m"},
            {"p", "q", "/", "u", "v", "w", "x", "y", "z", "."}
    };

    private final String [] arrayExtra = { "+", "#", ":", "~", "$", "-", "=", "&", "%", "!" };

    private String password;
    private final boolean needKey = true;
    private int [] numberPassword;

    public  void setPassword( String password ) {
        this.password = password;
        this.numberPassword = cleanPassword( this.password );
    }

    public boolean getNeedKey() {
        return this.needKey;
    }

    private String getExtraString() {
        int position = (int)(Math.random() * arrayExtra.length );
        return arrayExtra[ position ];
    }

    private int lookForLetter( String letter ) {

        for(int i=0; i<arrayVicCipher.length; i++) {

            for(int j=0; j<arrayVicCipher[0].length; j++) {
                if( arrayVicCipher[i][j] == null ) continue;
                if( letter.compareTo( arrayVicCipher[i][j] ) == 0 ) return j;
            }
        }

        return -1;
    }

    private int [] lookForNumbers( String letter ) {

        int [] myPsositions;

        for(int i=0; i<arrayMain.length; i++) {

            if( arrayMain[i] == null && i == 2 ) {
                for(int h=0; h<arrayDos.length; h++) {
                    if( arrayDos[h].compareTo( letter )  == 0 ) {
                        myPsositions = new int [2];
                        myPsositions[0] = 2;
                        myPsositions[1] = h;
                        return myPsositions;
                    }
                }
            }

            else if( arrayMain[i] == null && i == 6 ) {
                for(int j=0; j<arraySeis.length; j++) {
                    if( arraySeis[j].compareTo( letter )  == 0 ) {
                        myPsositions = new int [2];
                        myPsositions[0] = 6;
                        myPsositions[1] = j;
                        return myPsositions;
                    }

                }
            }

            else if( arrayMain[i].compareTo( letter )  == 0 ) {
                myPsositions = new int [1];
                myPsositions[0] = i;
                return myPsositions;
            }
        }

        return null;
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
        int [] arrayMessage = new int [ message.length() * 2 ];
        int indexMessage = 0;
        int [] arrayPositions;

        for(int i=0; i<message.length(); i++) {

            arrayPositions = lookForNumbers( message.substring(i,i+1) );

            switch( arrayPositions.length )  {

                case 1:
                    arrayMessage[ indexMessage] = arrayPositions[0];
                    indexMessage++;
                    break;

                case 2:
                    arrayMessage[ indexMessage] = arrayPositions[0];
                    indexMessage++;
                    arrayMessage[ indexMessage] = arrayPositions[1];
                    indexMessage++;
                    break;

                default:
                    break;
            }
        }

        int indexPassword = 0;
        int [] arrayCipher = new int [ indexMessage ];
        for(int f=0; f<arrayCipher.length; f++) {

            if ( indexPassword >= numberPassword.length ) indexPassword = 0;

            arrayCipher[f] = arrayMessage[f] + numberPassword[indexPassword];

            if( arrayCipher[f] >= 10) arrayCipher[f] = arrayCipher[f] - 10;
            indexPassword++;


        }

        for(int i=0; i<arrayCipher.length; i++) {

            if( arrayCipher[i] == 2 ) {
                i++;
                if( i >= arrayCipher.length  ) cipherMessage = cipherMessage.concat( getExtraString() );
                else cipherMessage = cipherMessage.concat( arrayDos[ arrayCipher[i] ]);
            }

            else if( arrayCipher[i] == 6 ) {
                i++;
                if( i >= arrayCipher.length  ) cipherMessage = cipherMessage.concat( getExtraString() );
                else cipherMessage = cipherMessage.concat( arraySeis[ arrayCipher[i] ] );
            }

            else {
                cipherMessage = cipherMessage.concat( arrayMain[ arrayCipher[i] ]);
            }

        }

        return cipherMessage;
    }

    public String doDecoding( String message ) {

        String cipherMessage = "";
        message = cleanMessage( message );
        int [] arrayMessage = new int [ message.length() * 2 ];
        int indexMessage = 0;
        int [] arrayPositions;

        for(int i=0; i<message.length(); i++) {

            arrayPositions = lookForNumbers( message.substring(i,i+1) );

            switch( arrayPositions.length )  {

                case 1:
                    arrayMessage[ indexMessage] = arrayPositions[0];
                    indexMessage++;
                    break;

                case 2:
                    arrayMessage[ indexMessage] = arrayPositions[0];
                    indexMessage++;
                    arrayMessage[ indexMessage] = arrayPositions[1];
                    indexMessage++;
                    break;

                default:
                    break;
            }
        }

        int indexPassword = 0;
        int [] arrayCipher = new int [ indexMessage ];

        for(int f=0; f<arrayCipher.length; f++) {

            if ( indexPassword >= numberPassword.length ) indexPassword = 0;

            if ( arrayMessage[f] == 0  && numberPassword[indexPassword] != 0 ) {
                arrayCipher[f] = Math.abs( 10 - numberPassword[indexPassword] );
            }
            else if ( arrayMessage[f] < numberPassword[indexPassword] ) {
                arrayCipher[f] = Math.abs( arrayMessage[f] + 10 - numberPassword[indexPassword] );
            }
            else {
                arrayCipher[f] = Math.abs( arrayMessage[f] - numberPassword[indexPassword] );
            }

            indexPassword++;
        }

        for(int i=0; i<arrayCipher.length; i++) {

            if( arrayCipher[i] == 2 ) {
                i++;
                if( i >= arrayCipher.length  ) cipherMessage = cipherMessage.concat( getExtraString() );
                else cipherMessage = cipherMessage.concat( arrayDos[ arrayCipher[i] ]);
            }

            else if( arrayCipher[i] == 6 ) {
                i++;
                if( i >= arrayCipher.length  ) cipherMessage = cipherMessage.concat( getExtraString() );
                else cipherMessage = cipherMessage.concat( arraySeis[ arrayCipher[i] ] );
            }

            else {
                cipherMessage = cipherMessage.concat( arrayMain[ arrayCipher[i] ]);
            }

        }

        return cipherMessage;
    }

    private int [] cleanPassword( String password ) {

        String myPassword = cleanMessage( password );
        String cleanPassword = "";


        for(int i = 0; i < myPassword.length(); i++) {

            if ( cleanPassword.length() == 0 )cleanPassword = cleanPassword.concat(myPassword.substring(i,i+1).toLowerCase());
            if ( myPassword.substring(i,i+1).compareTo(" ") == 0 )continue;

            else {
                boolean jumpChar = false;
                //String [] myCleanPassword = cleanPassword.split("");

                for(int j=0; j < cleanPassword.length(); j++) {

                    if( cleanPassword.substring(j,j+1).compareTo( myPassword.substring(i,i+1).toLowerCase() ) == 0 ) {
                        jumpChar = true;
                        break;
                    }
                }
                if(!jumpChar) {
                    cleanPassword = cleanPassword.concat(myPassword.substring(i,i+1).toLowerCase());
                }
            }
        }


        int [] arrayPassword = new int [ cleanPassword.length() * 2 ];
        int indexPassword = 0;
        int [] arrayPositions;


        for(int i=0; i<cleanPassword.length(); i++) {

            arrayPositions = lookForNumbers( cleanPassword.substring(i,i+1) );

            switch( arrayPositions.length )  {

                case 1:
                    arrayPassword[ indexPassword] = arrayPositions[0];
                    indexPassword++;
                    break;

                case 2:
                    arrayPassword[ indexPassword] = arrayPositions[0];
                    indexPassword++;
                    arrayPassword[ indexPassword] = arrayPositions[1];
                    indexPassword++;
                    break;

                default:
                    break;
            }
        }

        int [] numberPassword = new int[indexPassword];
        for(int i=0; i<numberPassword.length;i++) {
            numberPassword[i] = arrayPassword[i];
        }

        return numberPassword;



    }


}

