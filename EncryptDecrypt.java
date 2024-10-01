import java.util.Random;

public class EncryptDecrypt {

    public static void main(String[] args) {
        int length = 512;
        int minAscii = 33;
        int maxAscii = 126;

        char[] array1 = generateRandomCharArray(length, minAscii, maxAscii);
        char[] array2 = generateRandomCharArray(length, minAscii, maxAscii);

        System.out.println("Array 1: " + new String(array1));
        System.out.println("Array 2: " + new String(array2));

        char[] resultArray = new char[length];
        double[] calculation1Array = new double[length];
        double[] calculation2Array = new double[length];
        double[] calculation3Array = new double[length];

        for (int i = 0; i < length; i++) {
            char char1 = array1[i];
            char char2 = array2[i];

            int x = (int) char1;
            int y = (int) char2;

            int resultantAscii = (((x - 33) + (y - 33)) % 93) + 33;
            char resultChar = (char) resultantAscii;

            resultArray[i] = resultChar;
            calculation1Array[i] = ((2 * x) + y) + resultantAscii;
            calculation2Array[i] = ((3 * x) + y) + resultantAscii;
            calculation3Array[i] = ((5 * x) + y) + resultantAscii;
        }

        System.out.println("Resulting encrypted array: " + new String(resultArray));

        char[] decryptedXArray = new char[length];
        char[] decryptedYArray = new char[length];

        for (int i = 0; i < length; i++) {
            char charNum1 = resultArray[i];
            int num2 = (int) calculation1Array[i];
            int num3 = (int) calculation2Array[i];
            int num4 = (int) calculation3Array[i];

            decryptCharacter(charNum1, num2, num3, num4, decryptedXArray, decryptedYArray, i);
        }

        System.out.println("\nDecrypted X Array: " + new String(decryptedXArray));
        System.out.println("Decrypted Y Array: " + new String(decryptedYArray));
    }

    public static void decryptCharacter(char charNum1, int num2, int num3, int num4, char[] decryptedXArray, char[] decryptedYArray, int index) {
        int num1 = (int) charNum1;

        double[][] coefficients = {
                {2, 1, num2 - num1},
                {3, 1, num3 - num1}
        };

        double[] solution = solveEquations(coefficients);
        int roundedX = (int) Math.round(solution[0]);
        int roundedY = (int) Math.round(solution[1]);

        decryptedXArray[index] = (char) roundedX;
        decryptedYArray[index] = (char) roundedY;
    }

    public static double[] solveEquations(double[][] coefficients) {
        int n = coefficients.length;
        double[][] augmentedMatrix = new double[n][n + 1];

        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n + 1; j++) {
                augmentedMatrix[i][j] = coefficients[i][j];
            }
        }

        for (int i = 0; i < n - 1; i++) {
            int pivotRow = i;
            for (int j = i + 1; j < n; j++) {
                if (Math.abs(augmentedMatrix[j][i]) > Math.abs(augmentedMatrix[pivotRow][i])) {
                    pivotRow = j;
                }
            }

            if (pivotRow != i) {
                double[] tempRow = augmentedMatrix[i];
                augmentedMatrix[i] = augmentedMatrix[pivotRow];
                augmentedMatrix[pivotRow] = tempRow;
            }

            for (int j = i + 1; j < n; j++) {
                double factor = augmentedMatrix[j][i] / augmentedMatrix[i][i];
                for (int k = i; k < n + 1; k++) {
                    augmentedMatrix[j][k] -= factor * augmentedMatrix[i][k];
                }
            }
        }

        double[] solution = new double[n];
        for (int i = n - 1; i >= 0; i--) {
            solution[i] = augmentedMatrix[i][n] / augmentedMatrix[i][i];
            for (int j = i - 1; j >= 0; j--) {
                augmentedMatrix[j][n] -= augmentedMatrix[j][i] * solution[i];
            }
        }

        return solution;
    }

    public static char[] generateRandomCharArray(int length, int minAscii, int maxAscii) {
        Random random = new Random();
        char[] array = new char[length];

        for (int i = 0; i < length; i++) {
            int randomAscii = random.nextInt(maxAscii - minAscii + 1) + minAscii;
            array[i] = (char) randomAscii;
        }

        return array;
    }
}
