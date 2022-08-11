package com.example.cryptalgorithm;

public class CryptTest {

    public static void test() {
        HMsg msg = new HMsg();
        String password = "test1234";
        char[] testData = new char[]{186, 109, 3, 8, 8, 0, 58, 0};
        //char[] testData = new char[]{56, (-125 & 0xFF), 1, 8, 0, 42, 88, 102};

        int ss = 131 ^ 0xFF;

        msg.Ast_Crypt(testData, testData.length, password, true);
        msg.Ast_Crypt(testData, testData.length, password, false);
    }
}
