package com.example.cryptalgorithm;

import java.nio.ByteBuffer;

public class HMsg {

    public enum msgTypes {
        TCP,
        MQTT
    }

    public enum msgCommands {
        UPDATE_FIRMWARE(10),
        SET_USER_PASSWORD(50),
        DELETE_USER(51),
        SET_USER_LEVEL(52),
        DEVICE_SET_TIME(90),
        DEVICE_SETTIMEZONE(91),
        GET_USER_LEVEL(100),
        CHANGE_USER_PASSWORD(101),
        GET_PARAMETERS(102),
        SET_PARAMETERS(102),
        GET_DEVICE_VERSIONS(108),
        GET_DEVICE_STATUS(109),
        SET_TEMPERATURE(110),
        GET_SET_USER_SCHEDULE(111),
        GET_SET_TAP_SCHEDULE(112),
        GET_SET_SHOWER_SCHEDULE(113),
        GET_SCHEDULE_STATUS(114);

        msgCommands(int i) {}
    }

    public byte[] mainBytes;
    public byte[] encryptedBytes;
    public byte[] crcBytes;
    private msgTypes msgType = msgTypes.MQTT;   // 0 tcp, 1 mqtt
    private byte[] msgRawBytes = null;
    private String msgText = null;
    private msgCommands msgCommand;             // to change to enum

    // msg structure
    /*
    MT	UN	CRC	COMM	DLEN	DATA	FILL
    1	1	1   1	    1	    xxx 	xxx

    MT : Message Data Type (CHAR) = ‘B’ - BIN, ‘H’ - HEX
    UN : User Number (UID) = 0..4, 255 (BYTE). (see appendix 1.3)
    CRC : (BYTE). Incremented CRC (COMM + DLEN + DATA + FILL)
    COMM : Command (BYTE). (see comm.xlsx “commands”)
    DLEN : DATA length (BYTE).
    DATA : Command DATA (BYTES). (see comm.xlsx “commands”)
    FILL : (BYTES). So that the length of the message (ENCRYPTED part) is a multiple of 8.
    ENCRYPTED : This part is encrypted using the UN password (UPS). Encryption algorithm (see appendix 3.1)

     */

    public msgTypes getMsgType() {
        return msgType;
    }

    public void setMsgType(msgTypes type) {
        this.msgType = type;
    }

    public byte[] getMsgRawBytes() {
        return msgRawBytes;
    }

    public void setMsgRawBytes(byte[] rawBytes) {
        this.msgRawBytes = rawBytes;
    }

    public String getMsgText() {
        return msgText;
    }

    public void setMsgText(String text) {
        this.msgText = text;
    }

    public msgCommands getMsgCommand() {
        return msgCommand;
    }

    public void setMsgCommand(msgCommands command) {
        this.msgCommand = command;
    }


    //== BIT Cycle SHIFT Right/Left ==
    //	IN:
    //	@data - BYTE for SHIFT
    //	@count - Count BITS for SHIFT
    //	@shr - true = RIGHT Shift, false = LEFT shift

    public void Shift8_RL(char data, char count, boolean shr) {
        byte n;

        while (count != 0) {
            if (shr) {
                n = (byte)(data & 1);
                data >>= 1;

                if (n != 0) data |= 0x80;
            } else {
                n = (byte)(data & 0x80);
                data <<= 1;

                if (n != 0) data |= 1;
            }

            count--;
        }
    }


    //== BYTE Cycle SHIFT Up/Down ==
    //	IN:
    //	@data - BYTE array[8]
    //	@count - Count BITS for SHIFT
    //	@col - Column or BIT number for SHIFT
    //	@up � true = UpShift, false = DownShift

    public void Shift8_Col(char[] data, char count, char col, boolean up) {
        char[] cdata = data.clone();
        byte n;

        count %= 8;
        col = (char)(1 << col);

        for (int i = 0; i < 8; i++) {
            if (up) n = (byte)(i + count);
            else n = (byte)(i + 8 - count);

            if (n > 7) n -= 8;

            if ((data[i] & col) != (cdata[n] & col)) {
                data[i] ^= col;
            }
        }
    }


    //== com.example.cryptalgorithm.Main Algorithm. Encr/Decr 8 Byte array ==
    //	IN:
    //	@data � array[8] bytes
    //	@pass � password
    //	@encr � true = Encrypt, false = Decrypt

    public void Ast8Crypt(char[] data, String pass, boolean encr) {
        int pend = pass.length();
        char bp = 0, nnn = 0, ccc = 0;

        if (!encr) {
            for (int i = 0; i < 8; i++)
                Shift8_Col(data, (char)(i & 3), (char)i, encr);
        }

        for (int i = 0; i < pend; i++) {
            if (encr)
                bp = pass.charAt(i);
            else
                bp = pass.charAt(pend - 1 - i);

            nnn = (char)((char)(bp >> 1) & 7);      // count rotation
            ccc = (char)((char)(bp >> 4) & 7);      // row/col number

            if ((byte)(bp & 1) == 1) {
                bp = data[ccc];
                Shift8_RL(bp, nnn, encr);
                data[ccc] = bp;
            } else
                Shift8_Col(data, nnn, ccc, encr);
        }

        if (encr) {
            for (int i = 0; i < 8; i++)
                Shift8_Col(data, (char)(i & 3), (char)i, encr);
        }
    }


    //== Encr/Decr data ==
    //	IN:
    //	@data - data for encryption/decryption
    //	@size - data size
    //	@pass - zero term. password
    //	@encr - TRUE = encrypt, FALSE = decrypt
    //	RETURN:
    //	@data - encrypted/decrypted data

    public boolean Ast_Crypt(char[] data, int size, String pass, boolean encr) {
        size /= 8;      // x8 count parts

        if (size < 1 || pass.length() < 1)
            return false;

        for (int i = 0; i < size; i++) {
            char[] newData = new char[8];

            if ((i + 1) * 8 - i * 8 >= 0) System.arraycopy(data, i * 8, newData, i * 8 - i * 8, (i + 1) * 8 - i * 8);

            Ast8Crypt(newData, pass, encr);

            if ((i + 1) * 8 - i * 8 >= 0)
                System.arraycopy(newData, i * 8 - i * 8, data, i * 8, (i + 1) * 8 - i * 8);
        }

        return true;
    }

    /**
     * Command Generaten Code
     */

    private byte[] commands() {
        return mainBytes;
    }

    private byte[] encryption(String data) {
        return data.getBytes();
    }

    /**
     * MT : Message Data Type (CHAR) = ‘B’ - BIN, ‘H’ - HEX
     * @param data
     */
    private void MT(String data) {
        data = "B";
        mainBytes = data.getBytes();
    }

    /**
     *  UN : User Number (UID) = 0..4, 255
     * @param data
     */
    private void UN(String data) {
        byte[] mdata = encryption(data);
        byte[] bytes = ByteBuffer.allocate(5).put(mdata).array();

        for (byte mByte : bytes)
            mainBytes = addX(mainBytes.length, mainBytes, mByte);

        encryptedBytes = bytes;
    }

    /**
     * DLEN : DATA length (BYTE).
     * @param data
     */
    private void DLEN(byte[] data) {
        mainBytes = addX(mainBytes.length, mainBytes, (byte) data.length);
        encryptedBytes = addX(encryptedBytes.length, encryptedBytes, (byte) data.length);
        crcBytes = addX(crcBytes.length, crcBytes, (byte) data.length);
    }

    /**
     * COMM : Command (BYTE)
     *  Which follow comm.xlsx
     */
    private void COMM(int comm) {
        mainBytes = addX(mainBytes.length, mainBytes, (byte) comm);
        encryptedBytes = addX(encryptedBytes.length, encryptedBytes, (byte) comm);
        crcBytes = addX(crcBytes.length, crcBytes, (byte) comm);
    }

    /**
     * DATA : Command DATA (BYTES).
     */
    private void DATA(int comm, int user, String data) {
        mainBytes = addX(mainBytes.length, mainBytes, (byte) comm);
        mainBytes = addX(mainBytes.length, mainBytes, (byte) user);

        for (byte mByte : data.getBytes()) {
            mainBytes = addX(mainBytes.length, mainBytes, mByte);
            encryptedBytes = addX(encryptedBytes.length, encryptedBytes, mByte);
            crcBytes = addX(crcBytes.length, crcBytes, (byte) mByte);
        }
    }

    /**
     * (BYTES). So that the length of the message (ENCRYPTED part) is a multiple of 8
     */
    private void FILL(byte[] data) {
        int length = data.length * 8;

        mainBytes = addX(mainBytes.length, mainBytes, (byte)length);
        crcBytes = addX(crcBytes.length, crcBytes, (byte)length);
    }

    /**
     * CRC : (BYTE). Incremented CRC (COMM + DLEN + DATA + FILL)
     * @param data
     */
    private void CRC(byte[] data){
        encryptedBytes =  addX(encryptedBytes.length, encryptedBytes, (byte) data.length);
    }

    public static byte[] addX(int n, byte[] arr, byte x) {
        // create a new array of size n+1
        byte[] newarr = new byte[n + 1];

        // insert the elements from
        // the old array into the new array
        // insert all elements till n
        // then insert x at n+1
        if (n >= 0) System.arraycopy(arr, 0, newarr, 0, n);

        newarr[n] = x;

        return newarr;
    }
}
