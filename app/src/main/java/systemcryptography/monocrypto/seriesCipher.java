package systemcryptography.monocrypto;

import android.util.Log;

public class seriesCipher {

    private final boolean needKey = false;

    public boolean getNeedKey() {
        return this.needKey;
    }

    public String doCipher( String message ) {

        String [] arrayMessage = message.split("");
        int topNumber = arrayMessage.length;
        //Log.i("salida", "Limite: "+ topNumber );
        int [] arrayCandidates = new int [ topNumber ];
        int indexCandidates = 1;
        String cipherMessage = "";

        // find primes

        arrayCandidates[0] = 1;

        int candidate = 2;
        while( candidate < topNumber ) {
            int trialDivisor = 2;
            int prime = 1;

            while( ( trialDivisor * trialDivisor ) <= candidate ) {
                if( ( candidate % trialDivisor ) == 0 ) {
                    prime = 0;
                    break;
                }
                trialDivisor++;
            }

            if( prime != 0) {
                arrayCandidates[indexCandidates] = candidate;
                //Log.i("salida", "Numeros primos: "+ candidate );
                indexCandidates++;
            }

            candidate++;
        }

        for( int i=4; i<topNumber; i++ ) {
            if( ( i%2 ) == 0 ) {

                arrayCandidates[indexCandidates] = i;
                //Log.i("salida", "Numeros pares: "+ arrayCandidates[indexCandidates] );
                indexCandidates++;
            }
        }

        for( int j=9; j<topNumber; j++ ) {

            if( ( j%2 ) != 0  ) {
                boolean jumpNumber = true;
                for( int k=0; k<arrayCandidates.length; k++ ) {
                    if( arrayCandidates[k]  == j )jumpNumber = false;
                }
                if( jumpNumber ) {

                    arrayCandidates[indexCandidates] = j;
                    //Log.i("salida", "Numeros impares: "+ arrayCandidates[indexCandidates] );
                    indexCandidates++;
                }

            }
        }

        for(int i=0; i<arrayMessage.length; i++) {
            //Log.i("salida", "Numeros aleatorios: "+ arrayCandidates[ i ] );
            cipherMessage = cipherMessage.concat( arrayMessage[ arrayCandidates[ i ]  ]  );
        }

        return cipherMessage;
    }

    public String doDecoding( String message ) {

        String [] arrayMessage = message.split("");
        String [] arrayCipherMessage = new String [ arrayMessage.length ];
        int topNumber = arrayMessage.length;
        //Log.i("salida", "Limite: "+ topNumber );
        int [] arrayCandidates = new int [ topNumber ];
        int indexCandidates = 1;
        String cipherMessage = "";

        // find primes

        arrayCandidates[0] = 1;

        int candidate = 2;
        while( candidate < topNumber ) {
            int trialDivisor = 2;
            int prime = 1;

            while( ( trialDivisor * trialDivisor ) <= candidate ) {
                if( ( candidate % trialDivisor ) == 0 ) {
                    prime = 0;
                    break;
                }
                trialDivisor++;
            }

            if( prime != 0) {
                arrayCandidates[indexCandidates] = candidate;
                //Log.i("salida", "Numeros primos: "+ candidate );
                indexCandidates++;
            }

            candidate++;
        }

        for( int i=4; i<topNumber; i++ ) {
            if( ( i%2 ) == 0 ) {

                arrayCandidates[indexCandidates] = i;
                //Log.i("salida", "Numeros pares: "+ arrayCandidates[indexCandidates] );
                indexCandidates++;
            }
        }

        for( int j=9; j<topNumber; j++ ) {

            if( ( j%2 ) != 0  ) {
                boolean jumpNumber = true;
                for( int k=0; k<arrayCandidates.length; k++ ) {
                    if( arrayCandidates[k]  == j )jumpNumber = false;
                }
                if( jumpNumber ) {

                    arrayCandidates[indexCandidates] = j;
                    //Log.i("salida", "Numeros impares: "+ arrayCandidates[indexCandidates] );
                    indexCandidates++;
                }

            }
        }

        for(int i=0; i<message.length(); i++) {
            //Log.i("salida", "Numeros aleatorios: "+ arrayCandidates[ i ] );
            //cipherMessage = cipherMessage.concat( arrayMessage[ arrayCandidates[ i ]  ]  );
            Log.i("salida", "posicion : "+ arrayCandidates[ i ]+ " letra : "+  message.substring(i,i+1));
            arrayCipherMessage [ arrayCandidates[i] ] = message.substring(i,i+1);
        }

        for(int j=0; j<arrayCipherMessage.length; j++) {
            if(arrayCipherMessage [j] == null ) continue;
            cipherMessage = cipherMessage.concat( arrayCipherMessage [j] );
        }

        return cipherMessage;
    }
}